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
  review_status: "pending" | "approved" | "rejected";
  rejection_reason: string | null;
  status: string;
  created_at: string;
}

export interface SharedDocumentRecord {
  id: string;
  filename: string;
  owner_id: string | null;
  owner_name: string | null;
  owner_email: string | null;
  permissions: SharePermission[];
  file_size: number;
  content_type: string;
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
  expires_at: string | null;
  revoked_at: string | null;
}

export interface ActivityEvent {
  id: string;
  action: string;
  outcome: "success" | "denied" | "error";
  created_at: string;
  document_id: string | null;
  document_name: string | null;
  related_user_name: string | null;
  related_user_email: string | null;
}

export interface AdminActivityEvent {
  id: string;
  actor_email: string | null;
  action: string;
  outcome: "success" | "denied" | "error";
  created_at: string;
  document_id: string | null;
  document_name: string | null;
}

export interface AdminPendingDocument {
  id: string;
  name: string;
  owner_id: string;
  owner_name: string;
  owner_email: string;
  file_size: number;
  content_type: string;
  review_status: "pending" | "approved" | "rejected";
  created_at: string;
}

export interface AdminDocumentRecord extends AdminPendingDocument {
  category: string;
  status: string;
  rejection_reason: string | null;
  reviewed_at: string | null;
}

export interface AdminPermissionRecord {
  id: string;
  document_id: string;
  document_name: string;
  owner_email: string;
  grantee_id: string;
  grantee_name: string;
  grantee_email: string;
  granted_by_id: string;
  permission_level: "view" | "download" | "read" | "edit";
  is_revoked: boolean;
  granted_at: string;
  expires_at: string | null;
  revoked_at: string | null;
}

export interface AdminDashboardRecord {
  users: UserProfile[];
  activity: AdminActivityEvent[];
  pending_documents: AdminPendingDocument[];
  total_users: number;
  total_documents: number;
  pending_reviews: number;
  approved_documents: number;
  rejected_documents: number;
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

  sharedDocuments(token: string): Promise<SharedDocumentRecord[]> {
    return request<SharedDocumentRecord[]>("/documents/shared-with-me", token);
  },

  activity(token: string): Promise<ActivityEvent[]> {
    return request<ActivityEvent[]>("/activity/", token);
  },

  adminDashboard(token: string): Promise<AdminDashboardRecord> {
    return request<AdminDashboardRecord>("/admin/dashboard", token);
  },

  adminDocuments(
    token: string,
    filters: { owner?: string; owner_id?: string; filename?: string; review_status?: string; upload_from?: string; upload_to?: string },
  ): Promise<AdminDocumentRecord[]> {
    const params = new URLSearchParams();
    Object.entries(filters).forEach(([key, value]) => {
      if (value) params.set(key, value);
    });
    return request<AdminDocumentRecord[]>(`/admin/documents?${params.toString()}`, token);
  },

  adminAudit(
    token: string,
    filters: { actor?: string; action?: string; outcome?: string; date_from?: string; date_to?: string },
  ): Promise<AdminActivityEvent[]> {
    const params = new URLSearchParams();
    Object.entries(filters).forEach(([key, value]) => {
      if (value) params.set(key, value);
    });
    return request<AdminActivityEvent[]>(`/admin/audit?${params.toString()}`, token);
  },

  adminPermissions(token: string): Promise<AdminPermissionRecord[]> {
    return request<AdminPermissionRecord[]>("/admin/permissions", token);
  },

  revokeAdminPermission(token: string, permissionId: string): Promise<void> {
    return request<void>(`/admin/permissions/${encodeURIComponent(permissionId)}`, token, {
      method: "DELETE",
    });
  },

  setUserActive(token: string, userId: string, active: boolean): Promise<UserProfile> {
    return request<UserProfile>(
      `/admin/users/${encodeURIComponent(userId)}/${active ? "reactivate" : "deactivate"}`,
      token,
      { method: "POST" },
    );
  },

  async adminReport(
    token: string,
    filters: { actor?: string; action?: string; outcome?: string; date_from?: string; date_to?: string },
  ): Promise<Blob> {
    const params = new URLSearchParams();
    Object.entries(filters).forEach(([key, value]) => {
      if (value) params.set(key, value);
    });
    const response = await fetch(`${API_BASE_URL}/admin/reports/export?${params.toString()}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!response.ok) throw new ApiError(await errorMessage(response), response.status);
    return response.blob();
  },

  approveDocument(token: string, documentId: string): Promise<DocumentRecord> {
    return request<DocumentRecord>(
      `/admin/documents/${encodeURIComponent(documentId)}/approve`,
      token,
      { method: "POST" },
    );
  },

  rejectDocument(token: string, documentId: string, reason: string): Promise<DocumentRecord> {
    return request<DocumentRecord>(
      `/admin/documents/${encodeURIComponent(documentId)}/reject`,
      token,
      { method: "POST", body: JSON.stringify({ reason }) },
    );
  },

  async adminPreview(token: string, documentId: string): Promise<Blob> {
    const response = await fetch(
      `${API_BASE_URL}/admin/documents/${encodeURIComponent(documentId)}/preview`,
      { headers: { Authorization: "Bearer " + token } },
    );
    if (!response.ok) {
      throw new ApiError(await errorMessage(response), response.status);
    }
    return response.blob();
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
    expiresAt: string | null = null,
  ): Promise<DocumentShare> {
    return request<DocumentShare>(`/documents/${encodeURIComponent(documentId)}/shares`, token, {
      method: "POST",
      body: JSON.stringify({ user_id: userId, permission, expires_at: expiresAt }),
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

  async preview(token: string, documentId: string): Promise<Blob> {
    const response = await fetch(
      `${API_BASE_URL}/documents/${encodeURIComponent(documentId)}/preview`,
      { headers: { Authorization: `Bearer ${token}` } },
    );

    if (!response.ok) {
      throw new ApiError(await errorMessage(response), response.status);
    }

    return response.blob();
  },
};
