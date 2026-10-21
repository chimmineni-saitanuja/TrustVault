export interface UserProfile {
  id: string;
  name: string;
  email: string;
  role: "admin" | "owner" | "viewer";
  is_active: boolean;
  created_at: string;
}

export interface DocumentRecord {
  id: string;
  owner_id: string;
  name: string;
  category: string;
  file_size: number;
  content_type: string;
  status: string;
  created_at: string;
}

export interface DocumentShare {
  id: string;
  document_id: string;
  grantee_id: string;
  grantee_name: string;
  grantee_email: string;
  granted_by_id: string;
  permission_level: "view" | "download" | "read" | "edit";
  is_revoked: boolean;
  granted_at: string;
  revoked_at: string | null;
}

export type SharePermission = "view" | "download";

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000").replace(
  /\/+$/,
  "",
);

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function errorMessage(response: Response): Promise<string> {
  const body: unknown = await response.json().catch(() => null);
  if (typeof body === "object" && body !== null && "detail" in body) {
    if (typeof body.detail === "string") return body.detail;
    if (Array.isArray(body.detail)) {
      const messages = body.detail
        .map((item: unknown) =>
          typeof item === "object" &&
          item !== null &&
          "msg" in item &&
          typeof item.msg === "string"
            ? item.msg
            : null,
        )
        .filter((message): message is string => message !== null);
      if (messages.length > 0) return messages.join(" ");
    }
  }
  return `Request failed (${response.status})`;
}

async function request<T>(
  path: string,
  token: string,
  options: RequestInit = {},
): Promise<T> {
  const headers = new Headers(options.headers);
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  if (options.body && !(options.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    throw new ApiError(await errorMessage(response), response.status);
  }

  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

export const api = {
  register(name: string, email: string, password: string): Promise<UserProfile> {
    return request<UserProfile>("/auth/register", "", {
      method: "POST",
      body: JSON.stringify({ name, email, password }),
    });
  },

  login(email: string, password: string): Promise<{ access_token: string; token_type: "bearer" }> {
    return request<{ access_token: string; token_type: "bearer" }>("/auth/login", "", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
  },

  me(token: string): Promise<UserProfile> {
    return request<UserProfile>("/auth/me", token);
  },

  documents(token: string): Promise<DocumentRecord[]> {
    return request<DocumentRecord[]>("/documents/", token);
  },

  upload(token: string, file: File): Promise<DocumentRecord> {
    const form = new FormData();
    form.append("file", file);
    return request<DocumentRecord>("/documents/upload", token, { method: "POST", body: form });
  },

  shares(token: string, documentId: string): Promise<DocumentShare[]> {
    return request<DocumentShare[]>(`/documents/${encodeURIComponent(documentId)}/shares`, token);
  },

  grantShare(
    token: string,
    documentId: string,
    userId: string,
    permission: SharePermission,
  ): Promise<DocumentShare> {
    return request<DocumentShare>(`/documents/${encodeURIComponent(documentId)}/shares`, token, {
      method: "POST",
      body: JSON.stringify({ user_id: userId, permission }),
    });
  },

  revokeShare(token: string, documentId: string, shareId: string): Promise<void> {
    return request<void>(
      `/documents/${encodeURIComponent(documentId)}/shares/${encodeURIComponent(shareId)}`,
      token,
      { method: "DELETE" },
    );
  },

  async download(token: string, documentId: string): Promise<Blob> {
    const response = await fetch(
      `${API_BASE_URL}/documents/${encodeURIComponent(documentId)}/download`,
      { headers: { Authorization: `Bearer ${token}` } },
    );

    if (!response.ok) {
      throw new ApiError(await errorMessage(response), response.status);
    }

    return response.blob();
  },
};
