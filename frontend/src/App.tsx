import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent, type PointerEvent as ReactPointerEvent } from "react";
import {
  ArrowDownToLine,
  ArrowRight,
  Activity,
  Check,
  ChevronDown,
  CircleHelp,
  CloudUpload,
  Eye,
  File as FileIcon,
  FileImage,
  FileText,
  FolderClosed,
  KeyRound,
  LockKeyhole,
  LogOut,
  Mail,
  Plus,
  Search,
  ShieldCheck,
  Share2,
  Trash2,
  UserRound,
  X,
} from "lucide-react";

import { api, ApiError, type ActivityEvent, type AdminActivityEvent, type AdminDashboardRecord, type AdminDocumentRecord, type AdminPermissionRecord, type DocumentRecord, type DocumentShare, type SharePermission, type SharedDocumentRecord, type UserProfile } from "./api";

const TOKEN_KEY = "trustvault.access-token";
const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;
const ALLOWED_EXTENSIONS = new Set(["pdf", "png", "jpg", "jpeg", "txt"]);

type AuthMode = "login" | "register";
type Notice = { kind: "success" | "error"; text: string } | null;

function messageFromError(error: unknown): string {
  return error instanceof Error ? error.message : "Something went wrong. Please try again.";
}

function formatBytes(size: number): string {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(0)} KB`;
  return `${(size / (1024 * 1024)).toFixed(1)} MB`;
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
  }).format(new Date(value));
}

function formatActivityDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function fileIcon(contentType: string) {
  if (contentType.startsWith("image/")) return <FileImage aria-hidden="true" />;
  if (contentType === "application/pdf") return <FileText aria-hidden="true" />;
  return <FileIcon aria-hidden="true" />;
}

export default function App() {
  const [token, setToken] = useState(() => sessionStorage.getItem(TOKEN_KEY) ?? "");
  const [user, setUser] = useState<UserProfile | null>(null);
  const [documents, setDocuments] = useState<DocumentRecord[]>([]);
  const [sharedDocuments, setSharedDocuments] = useState<SharedDocumentRecord[]>([]);
  const [activityEvents, setActivityEvents] = useState<ActivityEvent[]>([]);
  const [showAllActivity, setShowAllActivity] = useState(false);
  const visibleActivityEvents = showAllActivity ? activityEvents : activityEvents.slice(0, 5);
  const [authMode, setAuthMode] = useState<AuthMode>("login");
  const [authLoading, setAuthLoading] = useState(false);
  const [loginUnlocking, setLoginUnlocking] = useState(false);
  const [sessionLoading, setSessionLoading] = useState(Boolean(token));
  const [documentsLoading, setDocumentsLoading] = useState(false);
  const [sharedLoading, setSharedLoading] = useState(Boolean(token));
  const [sharedError, setSharedError] = useState<string | null>(null);
  const [activityLoading, setActivityLoading] = useState(Boolean(token));
  const [activityError, setActivityError] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const uploadInputRef = useRef<HTMLInputElement>(null);
  const [search, setSearch] = useState("");
  const [notice, setNotice] = useState<Notice>(null);
  const [shareTarget, setShareTarget] = useState<string | null>(null);
  const [shareRows, setShareRows] = useState<Record<string, DocumentShare[]>>({});
  const [sharesLoading, setSharesLoading] = useState(false);
  const [shareBusy, setShareBusy] = useState(false);
  const [recipientId, setRecipientId] = useState("");
  const [permission, setPermission] = useState<SharePermission>("view");
  const [shareExpiresAt, setShareExpiresAt] = useState("");
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [previewingId, setPreviewingId] = useState<string | null>(null);

  const clearSession = useCallback(() => {
    sessionStorage.removeItem(TOKEN_KEY);
    setToken("");
    setUser(null);
    setDocuments([]);
    setSharedDocuments([]);
    setSharedError(null);
    setSharedLoading(false);
    setActivityEvents([]);
    setShowAllActivity(false);
    setActivityError(null);
    setActivityLoading(false);
    setShareRows({});
    setShareTarget(null);
  }, []);

  const reportRequestError = useCallback((error: unknown) => {
    if (error instanceof ApiError && error.status === 401) {
      clearSession();
      setNotice({ kind: "error", text: "Your session has expired. Sign in again to continue." });
      return;
    }
    setNotice({ kind: "error", text: messageFromError(error) });
  }, [clearSession]);

  const refreshDocuments = useCallback(async (activeToken: string) => {
    setDocumentsLoading(true);
    try {
      setDocuments(await api.documents(activeToken));
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) clearSession();
      throw error;
    } finally {
      setDocumentsLoading(false);
    }
  }, [clearSession]);

  const refreshSharedDocuments = useCallback(async (activeToken: string) => {
    setSharedLoading(true);
    setSharedError(null);
    try {
      setSharedDocuments(await api.sharedDocuments(activeToken));
    } catch (error) {
      setSharedError(messageFromError(error));
      if (error instanceof ApiError && error.status === 401) {
        clearSession();
        setNotice({ kind: "error", text: "Your session has expired. Sign in again to continue." });
      }
    } finally {
      setSharedLoading(false);
    }
  }, [clearSession]);

  const refreshActivity = useCallback(async (activeToken: string) => {
    setActivityLoading(true);
    setActivityError(null);
    try {
      setActivityEvents(await api.activity(activeToken));
    } catch (error) {
      setActivityError(messageFromError(error));
      if (error instanceof ApiError && error.status === 401) {
        clearSession();
        setNotice({ kind: "error", text: "Your session has expired. Sign in again to continue." });
      }
    } finally {
      setActivityLoading(false);
    }
  }, [clearSession]);

  useEffect(() => {
    if (!token) {
      setSessionLoading(false);
      setSharedLoading(false);
      setActivityLoading(false);
      return;
    }

    let active = true;
    const restoreSession = async () => {
      try {
        const profile = await api.me(token);
        if (!active) return;
        setUser(profile);
        if (profile.role === "admin") return;
        const rows = await api.documents(token);
        if (active) setDocuments(rows);
        await refreshSharedDocuments(token);
        await refreshActivity(token);
      } catch (error) {
        if (!active) return;
        if (error instanceof ApiError && error.status === 401) {
          clearSession();
          setNotice({ kind: "error", text: "Your session has expired. Sign in again to continue." });
        } else {
          setNotice({ kind: "error", text: messageFromError(error) });
        }
      } finally {
        setLoginUnlocking(false);
        if (active) setSessionLoading(false);
      }
    };

    void restoreSession();
    return () => {
      active = false;
    };
  }, [token, clearSession, refreshSharedDocuments, refreshActivity]);

  const visibleDocuments = useMemo(() => {
    const term = search.trim().toLowerCase();
    if (!term) return documents;
    return documents.filter((document) => document.name.toLowerCase().includes(term));
  }, [documents, search]);

  async function submitAuth(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setNotice(null);
    setAuthLoading(true);
    const form = new FormData(event.currentTarget);
    const email = String(form.get("email") ?? "").trim();
    const password = String(form.get("password") ?? "");

    try {
      if (authMode === "register") {
        const name = String(form.get("name") ?? "").trim();
        await api.register(name, email, password);
        setAuthMode("login");
        setNotice({ kind: "success", text: "Your account is ready. Sign in to open your vault." });
      } else {
        const result = await api.login(email, password);
        setLoginUnlocking(true);
        sessionStorage.setItem(TOKEN_KEY, result.access_token);
        setSessionLoading(true);
        setToken(result.access_token);
        setNotice(null);
      }
    } catch (error) {
      setNotice({ kind: "error", text: messageFromError(error) });
    } finally {
      setAuthLoading(false);
    }
  }

  function validateFile(file: File): string | null {
    const extension = file.name.split(".").pop()?.toLowerCase() ?? "";
    if (!ALLOWED_EXTENSIONS.has(extension)) {
      return "Choose a PDF, PNG, JPEG, or plain text file.";
    }
    if (file.size === 0) return "This file is empty. Choose a different file.";
    if (file.size > MAX_UPLOAD_BYTES) return "Files must be 10 MB or smaller.";
    return null;
  }

  async function uploadDocument(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!token || !selectedFile) return;
    const validation = validateFile(selectedFile);
    if (validation) {
      setNotice({ kind: "error", text: validation });
      return;
    }

    setUploading(true);
    setNotice(null);
    try {
      await api.upload(token, selectedFile);
      setSelectedFile(null);
      if (uploadInputRef.current) {
        uploadInputRef.current.value = "";
      }
      setNotice({ kind: "success", text: "Your document was uploaded to your private vault." });
      try {
        await refreshDocuments(token);
      } catch (error) {
        reportRequestError(error);
      }
      await refreshActivity(token);
    } catch (error) {
      await refreshActivity(token);
      reportRequestError(error);
    } finally {
      setUploading(false);
    }
  }

  async function toggleShares(documentId: string) {
    if (shareTarget === documentId) {
      setShareTarget(null);
      return;
    }
    setShareTarget(documentId);
    setRecipientId("");
    setNotice(null);
    if (shareRows[documentId]) return;

    setSharesLoading(true);
    try {
      const shares = await api.shares(token, documentId);
      setShareRows((current) => ({ ...current, [documentId]: shares }));
      await refreshActivity(token);
    } catch (error) {
      await refreshActivity(token);
      reportRequestError(error);
    } finally {
      setSharesLoading(false);
    }
  }

  async function grantShare(event: FormEvent<HTMLFormElement>, documentId: string) {
    event.preventDefault();
    const id = recipientId.trim();
    if (!id) {
      setNotice({ kind: "error", text: "Enter the recipient's user ID." });
      return;
    }
    const expiration = shareExpiresAt ? new Date(shareExpiresAt) : null;
    if (expiration && (!Number.isFinite(expiration.getTime()) || expiration <= new Date())) {
      setNotice({ kind: "error", text: "Choose an expiration date and time in the future." });
      return;
    }
    setShareBusy(true);
    setNotice(null);
    try {
      const share = await api.grantShare(
        token,
        documentId,
        id,
        permission,
        expiration?.toISOString() ?? null,
      );
      setShareRows((current) => ({
        ...current,
        [documentId]: [share, ...(current[documentId] ?? [])],
      }));
      setRecipientId("");
      setShareExpiresAt("");
      setNotice({ kind: "success", text: `Access granted with ${permission} permission.` });
      await refreshActivity(token);
    } catch (error) {
      await refreshActivity(token);
      reportRequestError(error);
    } finally {
      setShareBusy(false);
    }
  }

  async function revokeShare(documentId: string, shareId: string) {
    setShareBusy(true);
    setNotice(null);
    try {
      await api.revokeShare(token, documentId, shareId);
      setShareRows((current) => ({
        ...current,
        [documentId]: (current[documentId] ?? []).map((share) =>
          share.id === shareId
            ? { ...share, is_revoked: true, revoked_at: new Date().toISOString() }
            : share,
        ),
      }));
      setNotice({ kind: "success", text: "Access has been revoked." });
      await refreshActivity(token);
    } catch (error) {
      await refreshActivity(token);
      reportRequestError(error);
    } finally {
      setShareBusy(false);
    }
  }

  async function downloadDocument(document: Pick<DocumentRecord, "id" | "name">) {
    setDownloadingId(document.id);
    setNotice(null);
    try {
      const blob = await api.download(token, document.id);
      const objectUrl = URL.createObjectURL(blob);
      const anchor = window.document.createElement("a");
      anchor.href = objectUrl;
      anchor.download = document.name;
      anchor.style.display = "none";
      window.document.body.append(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
      setNotice({ kind: "success", text: `${document.name} is downloading.` });
      await refreshActivity(token);
    } catch (error) {
      await refreshActivity(token);
      reportRequestError(error);
    } finally {
      setDownloadingId(null);
    }
  }

  async function previewDocument(document: Pick<DocumentRecord, "id" | "content_type">) {
    if (
      document.content_type !== "application/pdf" &&
      !document.content_type.startsWith("image/")
    ) {
      setNotice({
        kind: "error",
        text: "Preview is not available for this file type. Use Download instead.",
      });
      return;
    }

    const previewTab = window.open("", "_blank");
    if (!previewTab) {
      setNotice({ kind: "error", text: "Allow pop-ups to open the document preview." });
      return;
    }

    previewTab.opener = null;
    previewTab.document.title = "Loading preview";
    previewTab.document.body.textContent = "Loading authorized document preview…";
    setPreviewingId(document.id);
    setNotice(null);
    try {
      const blob = await api.preview(token, document.id);
      const objectUrl = URL.createObjectURL(blob);
      previewTab.location.href = objectUrl;
      window.setTimeout(() => URL.revokeObjectURL(objectUrl), 5 * 60 * 1000);
      await refreshActivity(token);
    } catch (error) {
      previewTab.close();
      await refreshActivity(token);
      reportRequestError(error);
    } finally {
      setPreviewingId(null);
    }
  }

  if (sessionLoading) {
    return (
      <main className={`boot-screen${loginUnlocking ? " boot-screen-unlocking" : ""}`} aria-live="polite">
        <span className="brand-mark"><ShieldCheck size={22} /></span>
        <p>Unlocking your private workspace…</p>
      </main>
    );
  }

  if (!token || !user) {
    return (
      <AuthScreen
        mode={authMode}
        setMode={(mode) => {
          setAuthMode(mode);
          setNotice(null);
        }}
        loading={authLoading}
        notice={notice}
        onDismissNotice={() => setNotice(null)}
        onSubmit={submitAuth}
      />
    );
  }

  if (user.role === "admin") {
    return <AdminDashboard token={token} user={user} onLogout={clearSession} />;
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#" aria-label="TrustVault home">
          <span className="brand-mark"><ShieldCheck size={22} strokeWidth={2.2} /></span>
          <span>trust<span className="brand-light">vault</span></span>
        </a>

        <div className="workspace-label">WORKSPACE</div>
        <a className="nav-item nav-item-active" href="#my-vault">
          <FolderClosed size={18} />
          <span>My vault</span>
          <span className="nav-count">{documents.length}</span>
        </a>
        <a className="nav-item" href="#shared-with-me">
          <Share2 size={18} />
          <span>Shared with me</span>
          <span className="nav-count">{sharedDocuments.length}</span>
        </a>
        <a className="nav-item" href="#activity-log">
          <Activity size={18} />
          <span>Activity Log</span>
        </a>
        <div className="sidebar-note">
          <div className="sidebar-note-icon"><LockKeyhole size={17} /></div>
          <strong>Your files stay yours</strong>
          <p>Private storage, precise access controls, and a clear audit trail.</p>
        </div>

        <div className="sidebar-footer">
          <span className="avatar">{user.name.slice(0, 1).toUpperCase()}</span>
          <span className="profile-mini">
            <strong>{user.name}</strong>
            <small>{user.role}</small>
          </span>
          <button className="icon-button sidebar-logout" onClick={clearSession} aria-label="Log out" title="Log out">
            <LogOut size={17} />
          </button>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div className="breadcrumb"><span>Workspace</span><span className="crumb-slash">/</span><strong>My vault</strong></div>
          <div className="topbar-actions">
            <span className="secure-pill"><span className="secure-dot" /> Secure session</span>
            <button className="profile-button" onClick={clearSession} title="Log out">
              <span className="avatar avatar-small">{user.name.slice(0, 1).toUpperCase()}</span>
              <span className="profile-button-name">{user.name}</span>
              <LogOut size={16} />
            </button>
          </div>
        </header>

        <div className="page-content">
          <section className="welcome-row">
            <div>
              <p className="eyebrow">PRIVATE DOCUMENT WORKSPACE</p>
              <h1>Your vault, <span>in good hands.</span></h1>
              <p className="welcome-copy">Keep important files organized and share them only with the people you choose.</p>
            </div>
            <div className="identity-card">
              <span className="identity-icon"><UserRound size={18} /></span>
              <span>
                <small>Signed in as</small>
                <strong>{user.email}</strong>
                <small className="identity-user-id">User ID: {user.id}</small>
              </span>
              <span className="role-tag">{user.role}</span>
            </div>
          </section>

          {notice && <NoticeBanner notice={notice} onDismiss={() => setNotice(null)} />}

          <section className="stats-grid" aria-label="Vault overview">
            <div className="stat-card">
              <span className="stat-icon stat-purple"><FolderClosed size={19} /></span>
              <span className="stat-copy"><small>Documents in your vault</small><strong>{documents.length}</strong></span>
              <span className="stat-caption">Owned by you</span>
            </div>
            <div className="stat-card">
              <span className="stat-icon stat-green"><ShieldCheck size={19} /></span>
              <span className="stat-copy"><small>Account protection</small><strong className="stat-word">Active</strong></span>
              <span className="stat-caption">Verified session</span>
            </div>
            <div className="stat-card stat-help">
              <span className="stat-icon stat-blue"><CircleHelp size={19} /></span>
              <span className="stat-copy"><small>Share access</small><strong className="stat-word">You’re in control</strong></span>
              <span className="stat-caption">Grant or revoke anytime</span>
            </div>
          </section>

          <section className="upload-panel">
            <div className="upload-heading">
              <span className="upload-icon"><CloudUpload size={22} /></span>
              <div>
                <h2>Add a document</h2>
                <p>Private by default. You decide who can access it.</p>
              </div>
            </div>
            <form className="upload-form" onSubmit={uploadDocument}>
              <label className={`file-picker ${selectedFile ? "file-picker-selected" : ""}`}>
                <input
                  ref={uploadInputRef}
                  type="file"
                  accept=".pdf,.png,.jpg,.jpeg,.txt,application/pdf,image/png,image/jpeg,text/plain"
                  onChange={(event) => {
                    const file = event.currentTarget.files?.[0] ?? null;
                    setSelectedFile(file);
                    const validation = file ? validateFile(file) : null;
                    setNotice(validation ? { kind: "error", text: validation } : null);
                  }}
                  aria-label="Choose a document to upload"
                />
                <span className="file-picker-content">
                  {selectedFile ? <FileText size={19} /> : <Plus size={19} />}
                  <span>{selectedFile ? selectedFile.name : "Choose a file"}</span>
                  {selectedFile && <small>{formatBytes(selectedFile.size)}</small>}
                </span>
              </label>
              <button className="button button-primary upload-button" type="submit" disabled={!selectedFile || uploading}>
                {uploading ? <span className="spinner spinner-light" /> : <CloudUpload size={17} />}
                {uploading ? "Uploading…" : "Upload document"}
              </button>
            </form>
            <div className="upload-footnote"><LockKeyhole size={13} /> PDF, PNG, JPEG, or text · Up to 10 MB</div>
          </section>

          <section className="documents-section" id="my-vault">
            <div className="section-heading">
              <div>
                <p className="eyebrow">YOUR PRIVATE FILES</p>
                <h2>Documents <span className="heading-count">{documents.length}</span></h2>
              </div>
              <label className="search-box">
                <Search size={17} aria-hidden="true" />
                <span className="sr-only">Search documents</span>
                <input
                  type="search"
                  placeholder="Search your vault"
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                />
              </label>
            </div>

            {documentsLoading ? (
              <div className="state-card"><span className="spinner" /><span>Loading your documents…</span></div>
            ) : documents.length === 0 ? (
              <div className="empty-state">
                <span className="empty-icon"><FolderClosed size={24} /></span>
                <h3>Your vault is ready</h3>
                <p>Upload your first document above. It will be private to you until you share it.</p>
              </div>
            ) : visibleDocuments.length === 0 ? (
              <div className="state-card">No documents match “{search}”.</div>
            ) : (
              <div className="document-list">
                <div className="document-list-header">
                  <span>DOCUMENT</span><span>SIZE</span><span>ADDED</span><span className="actions-heading">ACTIONS</span>
                </div>
                {visibleDocuments.map((document) => (
                  <article className="document-card" key={document.id}>
                    <div className="document-row">
                      <div className="document-file">
                        <span className="file-icon">{fileIcon(document.content_type)}</span>
                        <span className="document-name-group">
                          <strong title={document.name}>{document.name}</strong>
                          <small>{document.content_type}</small>
                          <small className={`review-status review-${document.review_status}`}>
                            {document.review_status === "pending"
                              ? "Awaiting admin review"
                              : document.review_status === "rejected"
                                ? `Rejected: ${document.rejection_reason ?? "See administrator"}`
                                : "Approved"}
                          </small>
                        </span>
                      </div>
                      <span className="document-size">{formatBytes(document.file_size)}</span>
                      <span className="document-date">{formatDate(document.created_at)}</span>
                      <div className="document-actions">
                        <button
                          className="button button-quiet"
                          onClick={() => void toggleShares(document.id)}
                          disabled={document.review_status !== "approved"}
                          aria-expanded={shareTarget === document.id}
                          aria-controls={`shares-${document.id}`}
                        >
                          <Share2 size={15} /> Share <ChevronDown size={14} className={shareTarget === document.id ? "chevron-open" : ""} />
                        </button>
                        <button
                          className="button button-quiet document-view-button"
                          onClick={() => void previewDocument(document)}
                          disabled={previewingId === document.id || document.review_status !== "approved"}
                          aria-label={`View ${document.name}`}
                          title="View"
                        >
                          {previewingId === document.id
                            ? <span className="spinner spinner-small" />
                            : <Eye size={15} />}
                          View
                        </button>
                        <button
                          className="icon-button download-button"
                          onClick={() => void downloadDocument(document)}
                          disabled={downloadingId === document.id || document.review_status !== "approved"}
                          aria-label={`Download ${document.name}`}
                          title="Download"
                        >
                          {downloadingId === document.id ? <span className="spinner spinner-small" /> : <ArrowDownToLine size={18} />}
                        </button>
                      </div>
                    </div>

                    {shareTarget === document.id && (
                      <div className="share-panel" id={`shares-${document.id}`}>
                        <div className="share-panel-heading">
                          <div>
                            <p className="eyebrow">DOCUMENT ACCESS</p>
                            <h3>People with access</h3>
                          </div>
                          <span className="private-label"><LockKeyhole size={13} /> Owner controls</span>
                        </div>

                        <form className="grant-form" onSubmit={(event) => void grantShare(event, document.id)}>
                          <label>
                            <span>Recipient user ID</span>
                            <input
                              value={recipientId}
                              onChange={(event) => setRecipientId(event.target.value)}
                              placeholder="Paste an existing user's ID"
                              autoComplete="off"
                              required
                            />
                          </label>
                          <label className="permission-select">
                            <span>Permission</span>
                            <select value={permission} onChange={(event) => setPermission(event.target.value as SharePermission)}>
                              <option value="view">View metadata</option>
                              <option value="download">Download file</option>
                            </select>
                          </label>
                          <label>
                            <span>Expires (optional)</span>
                            <input
                              type="datetime-local"
                              value={shareExpiresAt}
                              onChange={(event) => setShareExpiresAt(event.target.value)}
                            />
                          </label>
                          <button className="button button-dark" type="submit" disabled={shareBusy}>
                            <Plus size={16} /> Grant access
                          </button>
                        </form>
                        <p className="share-hint">Set an optional expiration; otherwise access does not expire. Recipients see active grants in Shared with me.</p>

                        <div className="share-list">
                          {sharesLoading ? (
                            <div className="share-loading"><span className="spinner spinner-small" /> Loading access list…</div>
                          ) : (shareRows[document.id] ?? []).length === 0 ? (
                            <p className="no-shares">No one else has access to this document yet.</p>
                          ) : (
                            (shareRows[document.id] ?? []).map((share) => (
                              <div className={`share-row ${share.is_revoked ? "share-revoked" : ""}`} key={share.id}>
                                <span className="avatar avatar-share">{share.grantee_name.slice(0, 1).toUpperCase()}</span>
                                <span className="share-person">
                                  <strong>{share.grantee_name}</strong>
                                  <small>{share.grantee_email}</small>
                                  <small>
                                    {share.expires_at
                                      ? new Date(share.expires_at) <= new Date()
                                        ? "Expired"
                                        : `Expires ${formatActivityDate(share.expires_at)}`
                                      : "No expiration"}
                                  </small>
                                </span>
                                <span className={`permission-badge permission-${share.permission_level}`}>{share.permission_level}</span>
                                {share.is_revoked ? (
                                  <span className="revoked-label"><X size={13} /> Revoked</span>
                                ) : (
                                  <button
                                    className="revoke-button"
                                    onClick={() => void revokeShare(document.id, share.id)}
                                    disabled={shareBusy}
                                    aria-label={`Revoke ${share.permission_level} access for ${share.grantee_name}`}
                                  >
                                    <Trash2 size={14} /> Revoke
                                  </button>
                                )}
                              </div>
                            ))
                          )}
                        </div>
                      </div>
                    )}
                  </article>
                ))}
              </div>
            )}
          </section>

          <section className="documents-section shared-documents-section" id="shared-with-me">
            <div className="section-heading">
              <div>
                <p className="eyebrow">DOCUMENTS SHARED WITH YOU</p>
                <h2>Shared with me <span className="heading-count">{sharedDocuments.length}</span></h2>
              </div>
              <button
                className="button button-quiet"
                onClick={() => {
                  void (async () => {
                    await refreshSharedDocuments(token);
                    await refreshActivity(token);
                  })();
                }}
                disabled={sharedLoading}
              >
                {sharedLoading ? <span className="spinner spinner-small" /> : "Refresh"}
              </button>
            </div>

            {sharedLoading ? (
              <div className="state-card"><span className="spinner" /><span>Loading shared documents…</span></div>
            ) : sharedError ? (
              <div className="state-card shared-error" role="alert">
                <span>{sharedError}</span>
                <button
                  className="button button-quiet"
                  onClick={() => {
                    void (async () => {
                      await refreshSharedDocuments(token);
                      await refreshActivity(token);
                    })();
                  }}
                >
                  Try again
                </button>
              </div>
            ) : sharedDocuments.length === 0 ? (
              <div className="empty-state">
                <span className="empty-icon"><Share2 size={24} /></span>
                <h3>No documents shared with you yet</h3>
                <p>When someone grants you access to a document, it will appear here.</p>
              </div>
            ) : (
              <div className="document-list">
                <div className="document-list-header">
                  <span>DOCUMENT</span><span>SIZE</span><span>ADDED</span><span className="actions-heading">ACCESS</span>
                </div>
                {sharedDocuments.map((document) => (
                  <article className="document-card" key={document.id}>
                    <div className="document-row">
                      <div className="document-file">
                        <span className="file-icon">{fileIcon(document.content_type)}</span>
                        <span className="document-name-group">
                          <strong title={document.filename}>{document.filename}</strong>
                          <small>
                            Shared by {document.owner_name ?? document.owner_email ?? "Unknown owner"}
                            {document.owner_name && document.owner_email ? ` · ${document.owner_email}` : ""}
                          </small>
                        </span>
                      </div>
                      <span className="document-size">{formatBytes(document.file_size)}</span>
                      <span className="document-date">{formatDate(document.created_at)}</span>
                      <div className="document-actions">
                        {(document.permissions.includes("view") ||
                          document.permissions.includes("download")) && (
                          <button
                            className="button button-quiet document-view-button"
                            onClick={() => void previewDocument(document)}
                            disabled={previewingId === document.id}
                            aria-label={`View ${document.filename}`}
                            title="View"
                          >
                            {previewingId === document.id
                              ? <span className="spinner spinner-small" />
                              : <Eye size={15} />}
                            View
                          </button>
                        )}
                        {document.permissions.includes("download") && (
                          <button
                            className="icon-button download-button"
                            onClick={() => void downloadDocument({ id: document.id, name: document.filename })}
                            disabled={downloadingId === document.id}
                            aria-label={`Download ${document.filename}`}
                            title="Download"
                          >
                            {downloadingId === document.id
                              ? <span className="spinner spinner-small" />
                              : <ArrowDownToLine size={18} />}
                          </button>
                        )}
                      </div>
                    </div>
                  </article>
                ))}
              </div>
            )}
          </section>

          <section className="documents-section activity-section" id="activity-log">
            <div className="section-heading">
              <div>
                <p className="eyebrow">YOUR RECENT ACCOUNT ACTIVITY</p>
                <h2>Activity Log <span className="heading-count">{activityEvents.length}</span></h2>
              </div>
              <div className="section-actions">
                {activityEvents.length > 5 && (
                  <button
                    className="button button-quiet"
                    onClick={() => setShowAllActivity((showAll) => !showAll)}
                    aria-expanded={showAllActivity}
                  >
                    {showAllActivity ? "Show Recent" : <>View All <ArrowRight size={15} /></>}
                  </button>
                )}
                <button
                  className="button button-quiet"
                  onClick={() => void refreshActivity(token)}
                  disabled={activityLoading}
                >
                  {activityLoading ? <span className="spinner spinner-small" /> : "Refresh"}
                </button>
              </div>
            </div>

            {activityLoading ? (
              <div className="state-card"><span className="spinner" /><span>Loading activity…</span></div>
            ) : activityError ? (
              <div className="state-card shared-error" role="alert">
                <span>{activityError}</span>
                <button
                  className="button button-quiet"
                  onClick={() => void refreshActivity(token)}
                >
                  Try again
                </button>
              </div>
            ) : activityEvents.length === 0 ? (
              <div className="empty-state">
                <span className="empty-icon"><Activity size={24} /></span>
                <h3>No activity to show</h3>
                <p>Your account and document activity will appear here.</p>
              </div>
            ) : (
              <div className={`activity-list${showAllActivity ? "" : " activity-preview"}`}>
                {visibleActivityEvents.map((event) => (
                  <article className="activity-row" key={event.id}>
                    <span className={`activity-status activity-${event.outcome}`} aria-label={event.outcome} />
                    <div className="activity-details">
                      <strong>{event.action.replace(/[._]/g, " ")}</strong>
                      {(event.document_name || event.related_user_name || event.related_user_email) && (
                        <small>
                          {event.document_name && <>Document: {event.document_name}</>}
                          {event.document_name && (event.related_user_name || event.related_user_email) && " · "}
                          {(event.related_user_name || event.related_user_email) && (
                            <>User: {event.related_user_name ?? event.related_user_email}</>
                          )}
                          {event.related_user_name && event.related_user_email && ` (${event.related_user_email})`}
                        </small>
                      )}
                    </div>
                    <span className={`activity-outcome activity-outcome-${event.outcome}`}>
                      {event.outcome}
                    </span>
                    <time dateTime={event.created_at}>{formatActivityDate(event.created_at)}</time>
                  </article>
                ))}
              </div>
            )}
            <p className="activity-note">Showing {showAllActivity ? "all" : "up to 5"} of up to 100 recent events performed by your account. Sensitive request details are not displayed.</p>
          </section>

          <footer className="page-footer">
            <span><ShieldCheck size={15} /> Protected by TrustVault</span>
            <span>Files are private until you grant access.</span>
          </footer>
        </div>
      </main>
    </div>
  );
}

function AdminDashboard({
  token,
  user,
  onLogout,
}: {
  token: string;
  user: UserProfile;
  onLogout: () => void;
}) {
  const [dashboard, setDashboard] = useState<AdminDashboardRecord | null>(null);
  const [adminDocuments, setAdminDocuments] = useState<AdminDocumentRecord[]>([]);
  const [adminPermissions, setAdminPermissions] = useState<AdminPermissionRecord[]>([]);
  const [auditEvents, setAuditEvents] = useState<AdminActivityEvent[]>([]);
  const [showAllAudit, setShowAllAudit] = useState(false);
  const visibleAuditEvents = showAllAudit ? auditEvents : auditEvents.slice(0, 5);
  const [loading, setLoading] = useState(true);
  const [busyDocumentId, setBusyDocumentId] = useState<string | null>(null);
  const [previewingDocumentId, setPreviewingDocumentId] = useState<string | null>(null);
  const [busyUserId, setBusyUserId] = useState<string | null>(null);
  const [busyPermissionId, setBusyPermissionId] = useState<string | null>(null);
  const [rejectionReasons, setRejectionReasons] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [documentFilters, setDocumentFilters] = useState({ owner: "", filename: "", review_status: "", upload_from: "", upload_to: "" });
  const [auditFilters, setAuditFilters] = useState({ actor: "", action: "", outcome: "", date_from: "", date_to: "" });

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [nextDashboard, nextDocuments, nextPermissions, nextAudit] = await Promise.all([
        api.adminDashboard(token),
        api.adminDocuments(token, {}),
        api.adminPermissions(token),
        api.adminAudit(token, {}),
      ]);
      setDashboard(nextDashboard);
      setAdminDocuments(nextDocuments);
      setAdminPermissions(nextPermissions);
      setAuditEvents(nextAudit);
    } catch (requestError) {
      if (requestError instanceof ApiError && requestError.status === 401) {
        onLogout();
      }
      setError(messageFromError(requestError));
    } finally {
      setLoading(false);
    }
  }, [token, onLogout]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function previewPendingDocument(documentId: string) {
    const previewTab = window.open("", "_blank");
    if (!previewTab) {
      setError("Allow pop-ups to open the review preview.");
      return;
    }
    previewTab.opener = null;
    previewTab.document.title = "Loading review preview";
    previewTab.document.body.textContent = "Loading authorized document preview…";
    setPreviewingDocumentId(documentId);
    setError(null);
    try {
      const blob = await api.adminPreview(token, documentId);
      const objectUrl = URL.createObjectURL(blob);
      previewTab.location.href = objectUrl;
      window.setTimeout(() => URL.revokeObjectURL(objectUrl), 5 * 60 * 1000);
    } catch (requestError) {
      previewTab.close();
      setError(messageFromError(requestError));
      if (requestError instanceof ApiError && requestError.status === 401) {
        onLogout();
      }
    } finally {
      setPreviewingDocumentId(null);
    }
  }

  async function reviewDocument(documentId: string, decision: "approve" | "reject") {
    const reason = rejectionReasons[documentId]?.trim() ?? "";
    if (decision === "reject" && !reason) {
      setError("Enter a reason before rejecting this document.");
      return;
    }

    setBusyDocumentId(documentId);
    setError(null);
    setNotice(null);
    try {
      if (decision === "approve") {
        await api.approveDocument(token, documentId);
      } else {
        await api.rejectDocument(token, documentId, reason);
      }
      setRejectionReasons((current) => {
        const updated = { ...current };
        delete updated[documentId];
        return updated;
      });
      setNotice(decision === "approve" ? "Document approved." : "Document rejected.");
      await refresh();
    } catch (requestError) {
      if (requestError instanceof ApiError && requestError.status === 401) {
        onLogout();
      }
      setError(messageFromError(requestError));
    } finally {
      setBusyDocumentId(null);
    }
  }

  async function filterDocuments(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    try {
      setAdminDocuments(await api.adminDocuments(token, documentFilters));
    } catch (requestError) {
      setError(messageFromError(requestError));
    }
  }

  async function filterAudit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    try {
      setAuditEvents(await api.adminAudit(token, auditFilters));
    } catch (requestError) {
      setError(messageFromError(requestError));
    }
  }

  async function updateAccountStatus(account: UserProfile) {
    setBusyUserId(account.id);
    setError(null);
    try {
      const updated = await api.setUserActive(token, account.id, !account.is_active);
      setDashboard((current) =>
        current
          ? { ...current, users: current.users.map((row) => (row.id === updated.id ? updated : row)) }
          : current,
      );
      setNotice(`${updated.name} is now ${updated.is_active ? "active" : "inactive"}.`);
      setAuditEvents(await api.adminAudit(token, auditFilters));
    } catch (requestError) {
      setError(messageFromError(requestError));
    } finally {
      setBusyUserId(null);
    }
  }

  async function revokeAdminGrant(permission: AdminPermissionRecord) {
    setBusyPermissionId(permission.id);
    setError(null);
    try {
      await api.revokeAdminPermission(token, permission.id);
      setAdminPermissions((current) =>
        current.map((row) =>
          row.id === permission.id
            ? { ...row, is_revoked: true, revoked_at: new Date().toISOString() }
            : row,
        ),
      );
      setNotice(`Access to ${permission.document_name} has been revoked.`);
      setAuditEvents(await api.adminAudit(token, auditFilters));
    } catch (requestError) {
      setError(messageFromError(requestError));
    } finally {
      setBusyPermissionId(null);
    }
  }

  async function exportReport() {
    setError(null);
    try {
      const report = await api.adminReport(token, auditFilters);
      const objectUrl = URL.createObjectURL(report);
      const anchor = window.document.createElement("a");
      anchor.href = objectUrl;
      anchor.download = "trustvault-admin-report.csv";
      anchor.style.display = "none";
      window.document.body.append(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
    } catch (requestError) {
      setError(messageFromError(requestError));
    }
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#" aria-label="TrustVault home">
          <span className="brand-mark"><ShieldCheck size={22} strokeWidth={2.2} /></span>
          <span>trust<span className="brand-light">vault</span></span>
        </a>
        <div className="workspace-label">ADMINISTRATION</div>
        <a className="nav-item" href="#admin-overview">
          <Activity size={18} />
          <span>Overview</span>
        </a>
        <a className="nav-item" href="#admin-documents">
          <FileText size={18} />
          <span>All documents</span>
          <span className="nav-count">{dashboard?.total_documents ?? 0}</span>
        </a>
        <a className="nav-item nav-item-active" href="#admin-review">
          <Check size={18} />
          <span>Document review</span>
          <span className="nav-count">{dashboard?.pending_documents.length ?? 0}</span>
        </a>
        <a className="nav-item" href="#admin-users">
          <UserRound size={18} />
          <span>Users</span>
          <span className="nav-count">{dashboard?.users.length ?? 0}</span>
        </a>
        <a className="nav-item" href="#admin-activity">
          <Activity size={18} />
          <span>Audit activity</span>
        </a>
        <a className="nav-item" href="#admin-permissions">
          <KeyRound size={18} />
          <span>Permissions</span>
        </a>
        <div className="sidebar-footer">
          <span className="avatar">{user.name.slice(0, 1).toUpperCase()}</span>
          <span className="profile-mini"><strong>{user.name}</strong><small>admin</small></span>
          <button className="icon-button sidebar-logout" onClick={onLogout} aria-label="Log out" title="Log out">
            <LogOut size={17} />
          </button>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div className="breadcrumb"><span>TrustVault</span><span className="crumb-slash">/</span><strong>Admin dashboard</strong></div>
          <div className="topbar-actions">
            <span className="secure-pill"><span className="secure-dot" /> Administrator session</span>
            <button className="profile-button" onClick={onLogout} title="Log out">
              <span className="avatar avatar-small">{user.name.slice(0, 1).toUpperCase()}</span>
              <span className="profile-button-name">{user.name}</span>
              <LogOut size={16} />
            </button>
          </div>
        </header>
        <div className="page-content">
          <section className="welcome-row">
            <div>
              <p className="eyebrow">ADMINISTRATION</p>
              <h1>Admin <span>Dashboard.</span></h1>
              <p className="welcome-copy">Review uploaded documents and monitor TrustVault activity.</p>
            </div>
            <span className="role-tag">Administrator</span>
          </section>
          {error && <div className="state-card shared-error" role="alert">{error}</div>}
          {notice && <div className="state-card" role="status">{notice}</div>}

          <section className="documents-section admin-section" id="admin-overview">
            <div className="section-heading">
              <div><p className="eyebrow">TRUSTVAULT AT A GLANCE</p><h2>Overview</h2></div>
              <button className="button button-quiet" onClick={() => void refresh()} disabled={loading}>Refresh dashboard</button>
            </div>
            {dashboard && (
              <div className="admin-metrics">
                <article><span>Total users</span><strong>{dashboard.total_users}</strong></article>
                <article><span>Total documents</span><strong>{dashboard.total_documents}</strong></article>
                <article><span>Pending reviews</span><strong>{dashboard.pending_reviews}</strong></article>
                <article><span>Approved</span><strong>{dashboard.approved_documents}</strong></article>
                <article><span>Rejected</span><strong>{dashboard.rejected_documents}</strong></article>
              </div>
            )}
          </section>

          <section className="documents-section admin-section" id="admin-review">
            <div className="section-heading">
              <div><p className="eyebrow">OWNER SUBMISSIONS</p><h2>Awaiting review <span className="heading-count">{dashboard?.pending_documents.length ?? 0}</span></h2></div>
              <button className="button button-quiet" onClick={() => void refresh()} disabled={loading}>Refresh</button>
            </div>
            {loading ? (
              <div className="state-card"><span className="spinner" /><span>Loading administrator dashboard…</span></div>
            ) : !dashboard?.pending_documents.length ? (
              <div className="empty-state"><span className="empty-icon"><Check size={24} /></span><h3>No documents are waiting</h3><p>New uploads will appear here for review.</p></div>
            ) : (
              <div className="admin-review-list">
                {dashboard.pending_documents.map((document) => (
                  <article className="admin-review-card" key={document.id}>
                    <div className="document-file">
                      <span className="file-icon">{fileIcon(document.content_type)}</span>
                      <span className="document-name-group">
                        <strong title={document.name}>{document.name}</strong>
                        <small>{document.owner_name} · {document.owner_email}</small>
                        <small>{formatBytes(document.file_size)} · Submitted {formatActivityDate(document.created_at)}</small>
                      </span>
                    </div>
                    <label className="admin-rejection-field">
                      <span>Rejection reason (required to reject)</span>
                      <input
                        value={rejectionReasons[document.id] ?? ""}
                        maxLength={500}
                        onChange={(event) =>
                          setRejectionReasons((current) => ({
                            ...current,
                            [document.id]: event.target.value,
                          }))
                        }
                        placeholder="Explain what needs to change"
                      />
                    </label>
                    <div className="admin-review-actions">
                      <button
                        className="button button-quiet"
                        onClick={() => void previewPendingDocument(document.id)}
                        disabled={previewingDocumentId === document.id}
                      >
                        <Eye size={15} /> {previewingDocumentId === document.id ? "Opening…" : "Review file"}
                      </button>
                      <button
                        className="button button-primary"
                        onClick={() => void reviewDocument(document.id, "approve")}
                        disabled={busyDocumentId === document.id}
                      >
                        <Check size={15} /> Approve
                      </button>
                      <button
                        className="button button-reject"
                        onClick={() => void reviewDocument(document.id, "reject")}
                        disabled={busyDocumentId === document.id}
                      >
                        <X size={15} /> Reject
                      </button>
                    </div>
                  </article>
                ))}
              </div>
            )}
          </section>

          <section className="documents-section admin-section" id="admin-documents">
            <div className="section-heading">
              <div><p className="eyebrow">DOCUMENT CATALOG</p><h2>All documents <span className="heading-count">{adminDocuments.length}</span></h2></div>
            </div>
            <form className="admin-filter-form" onSubmit={(event) => void filterDocuments(event)}>
              <label>Owner<input value={documentFilters.owner} onChange={(event) => setDocumentFilters({ ...documentFilters, owner: event.target.value })} placeholder="Name, email, or user ID" /></label>
              <label>Filename<input value={documentFilters.filename} onChange={(event) => setDocumentFilters({ ...documentFilters, filename: event.target.value })} placeholder="Search filename" /></label>
              <label>Review status<select value={documentFilters.review_status} onChange={(event) => setDocumentFilters({ ...documentFilters, review_status: event.target.value })}><option value="">All statuses</option><option value="pending">Pending</option><option value="approved">Approved</option><option value="rejected">Rejected</option></select></label>
              <label>Uploaded from<input type="date" value={documentFilters.upload_from.slice(0, 10)} onChange={(event) => setDocumentFilters({ ...documentFilters, upload_from: event.target.value ? `${event.target.value}T00:00:00` : "" })} /></label>
              <label>Uploaded to<input type="date" value={documentFilters.upload_to.slice(0, 10)} onChange={(event) => setDocumentFilters({ ...documentFilters, upload_to: event.target.value ? `${event.target.value}T23:59:59` : "" })} /></label>
              <button className="button button-dark" type="submit">Search documents</button>
            </form>
            {!loading && (
              adminDocuments.length ? (
                <div className="admin-review-list">
                  {adminDocuments.map((document) => (
                    <article className="admin-review-card" key={document.id}>
                      <div className="document-file">
                        <span className="file-icon">{fileIcon(document.content_type)}</span>
                        <span className="document-name-group">
                          <strong title={document.name}>{document.name}</strong>
                          <small>{document.owner_name} · {document.owner_email}</small>
                          <small>{document.category} · {formatBytes(document.file_size)} · {document.content_type}</small>
                          <small>Uploaded {formatActivityDate(document.created_at)} · {document.status}</small>
                          <small className={`review-status review-${document.review_status}`}>{document.review_status}{document.rejection_reason ? `: ${document.rejection_reason}` : ""}</small>
                        </span>
                      </div>
                      <div className="admin-review-actions">
                        <button className="button button-quiet" onClick={() => void previewPendingDocument(document.id)} disabled={previewingDocumentId === document.id}>
                          <Eye size={15} /> Protected preview
                        </button>
                      </div>
                    </article>
                  ))}
                </div>
              ) : <div className="empty-state"><h3>No documents match these filters</h3></div>
            )}
          </section>

          <section className="documents-section admin-section" id="admin-users">
            <div className="section-heading">
              <div><p className="eyebrow">ACCOUNT DIRECTORY</p><h2>Users <span className="heading-count">{dashboard?.users.length ?? 0}</span></h2></div>
            </div>
            {!loading && dashboard && (
              <div className="activity-list">
                {dashboard.users.map((account) => (
                  <div className="activity-row" key={account.id}>
                    <span className={`activity-status ${account.is_active ? "" : "activity-denied"}`} />
                    <span className="activity-details">
                      <strong>{account.name}</strong>
                      <small>{account.email} · {account.id}</small>
                    </span>
                    <span className="role-tag">{account.role}</span>
                    <time>{account.is_active ? "Active" : "Inactive"} · Joined {formatDate(account.created_at)}</time>
                    <button className="button button-quiet" onClick={() => void updateAccountStatus(account)} disabled={busyUserId === account.id || (account.role === "admin" && account.id === user.id && account.is_active)}>
                      {busyUserId === account.id ? <span className="spinner spinner-small" /> : account.is_active ? "Deactivate" : "Reactivate"}
                    </button>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section className="documents-section admin-section" id="admin-permissions">
            <div className="section-heading">
              <div><p className="eyebrow">ACCESS CONTROL</p><h2>Document grants <span className="heading-count">{adminPermissions.length}</span></h2></div>
              <button className="button button-quiet" onClick={() => void refresh()} disabled={loading}>Refresh</button>
            </div>
            <div className="activity-list">
              {adminPermissions.length ? adminPermissions.map((grant) => (
                <div className="activity-row" key={grant.id}>
                  <span className={`activity-status ${grant.is_revoked ? "activity-denied" : ""}`} />
                  <span className="activity-details">
                    <strong>{grant.document_name} · {grant.permission_level}</strong>
                    <small>{grant.grantee_name} ({grant.grantee_email}) · Owner {grant.owner_email}</small>
                    <small>Granted {formatActivityDate(grant.granted_at)}{grant.expires_at ? ` · Expires ${formatActivityDate(grant.expires_at)}` : ""}</small>
                  </span>
                  {grant.is_revoked ? <span className="revoked-label">Revoked</span> : (
                    <button className="revoke-button" onClick={() => void revokeAdminGrant(grant)} disabled={busyPermissionId === grant.id}>
                      {busyPermissionId === grant.id ? <span className="spinner spinner-small" /> : <><Trash2 size={14} /> Revoke</>}
                    </button>
                  )}
                </div>
              )) : <div className="empty-state"><h3>No document grants</h3></div>}
            </div>
          </section>

          <section className="documents-section admin-section" id="admin-activity">
            <div className="section-heading">
              <div><p className="eyebrow">SECURITY AUDIT</p><h2>Security &amp; Audit Center <span className="heading-count">{auditEvents.length}</span></h2></div>
              <div className="section-actions">
                {auditEvents.length > 5 && (
                  <button
                    className="button button-quiet"
                    onClick={() => setShowAllAudit((showAll) => !showAll)}
                    aria-expanded={showAllAudit}
                  >
                    {showAllAudit ? "Show Recent" : <>View All <ArrowRight size={15} /></>}
                  </button>
                )}
                <button className="button button-quiet" onClick={() => void exportReport()}>Export filtered report</button>
              </div>
            </div>
            <form className="admin-filter-form" onSubmit={(event) => void filterAudit(event)}>
              <label>Actor<input value={auditFilters.actor} onChange={(event) => setAuditFilters({ ...auditFilters, actor: event.target.value })} placeholder="Email contains…" /></label>
              <label>Action<input value={auditFilters.action} onChange={(event) => setAuditFilters({ ...auditFilters, action: event.target.value })} placeholder="Exact action name" /></label>
              <label>Outcome<select value={auditFilters.outcome} onChange={(event) => setAuditFilters({ ...auditFilters, outcome: event.target.value })}><option value="">Any outcome</option><option value="success">Success</option><option value="denied">Denied</option><option value="error">Error</option></select></label>
              <label>From<input type="date" value={auditFilters.date_from.slice(0, 10)} onChange={(event) => setAuditFilters({ ...auditFilters, date_from: event.target.value ? `${event.target.value}T00:00:00` : "" })} /></label>
              <label>To<input type="date" value={auditFilters.date_to.slice(0, 10)} onChange={(event) => setAuditFilters({ ...auditFilters, date_to: event.target.value ? `${event.target.value}T23:59:59` : "" })} /></label>
              <button className="button button-dark" type="submit">Filter audit</button>
            </form>
            {!loading && (
              auditEvents.length ? (
                <div className={`activity-list${showAllAudit ? "" : " activity-preview"}`}>
                  {visibleAuditEvents.map((event) => (
                    <div className="activity-row" key={event.id}>
                      <span className={`activity-status ${event.outcome === "denied" ? "activity-denied" : event.outcome === "error" ? "activity-error" : ""}`} />
                      <span className="activity-details">
                        <strong>{event.action.replaceAll(".", " ")}</strong>
                        <small>{event.actor_email ?? "Unknown actor"}{event.document_name ? ` · ${event.document_name}` : ""}</small>
                      </span>
                      <span className={`activity-outcome activity-outcome-${event.outcome}`}>{event.outcome}</span>
                      <time>{formatActivityDate(event.created_at)}</time>
                    </div>
                  ))}
                </div>
              ) : <div className="empty-state"><h3>No audit activity matches these filters</h3></div>
            )}
            <p className="activity-note">Audit metadata, addresses, and storage details are not exposed.</p>
          </section>
        </div>
      </main>
    </div>
  );
}

interface AuthScreenProps {
  mode: AuthMode;
  setMode: (mode: AuthMode) => void;
  loading: boolean;
  notice: Notice;
  onDismissNotice: () => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
}

function AuthScreen({ mode, setMode, loading, notice, onDismissNotice, onSubmit }: AuthScreenProps) {
  const registering = mode === "register";
  const vaultSceneRef = useRef<HTMLDivElement>(null);

  function moveVaultScene(event: ReactPointerEvent<HTMLElement>) {
    if (
      event.pointerType !== "mouse" ||
      window.matchMedia("(max-width: 780px)").matches ||
      window.matchMedia("(prefers-reduced-motion: reduce)").matches
    ) return;
    const bounds = event.currentTarget.getBoundingClientRect();
    const horizontal = (event.clientX - bounds.left) / bounds.width - 0.5;
    const vertical = (event.clientY - bounds.top) / bounds.height - 0.5;
    vaultSceneRef.current?.style.setProperty("--pointer-x", `${horizontal * 9}px`);
    vaultSceneRef.current?.style.setProperty("--pointer-y", `${vertical * 7}px`);
  }

  function resetVaultScene() {
    vaultSceneRef.current?.style.setProperty("--pointer-x", "0px");
    vaultSceneRef.current?.style.setProperty("--pointer-y", "0px");
  }

  return (
    <main className="auth-layout" onPointerMove={moveVaultScene} onPointerLeave={resetVaultScene}>
      <section className="auth-story">
        <div className="vault-scene" aria-hidden="true" ref={vaultSceneRef}>
          <span className="vault-beam vault-beam-one" />
          <span className="vault-beam vault-beam-two" />
          <span className="vault-ring vault-ring-one" />
          <span className="vault-ring vault-ring-two" />
          <span className="vault-ring vault-ring-three" />
          <span className="vault-core">
            <ShieldCheck className="vault-shield" size={88} strokeWidth={1.15} />
          </span>
          <span className="vault-document vault-document-one"><FileText size={20} /><i>PDF</i></span>
          <span className="vault-document vault-document-two"><FileImage size={19} /><i>IMAGE</i></span>
          <span className="vault-document vault-document-three"><FileText size={18} /><i>FILE</i></span>
          <span className="vault-particle vault-particle-one" />
          <span className="vault-particle vault-particle-two" />
          <span className="vault-particle vault-particle-three" />
          <span className="vault-particle vault-particle-four" />
          <span className="vault-trail vault-trail-one" />
          <span className="vault-trail vault-trail-two" />
          <span className="vault-trail vault-trail-three" />
        </div>
        <a className="brand brand-light" href="#" aria-label="TrustVault">
          <span className="brand-mark brand-mark-glass"><ShieldCheck size={22} strokeWidth={2.2} /></span>
          <span>trust<span className="brand-light-word">vault</span></span>
        </a>
        <div className="story-content">
          <span className="story-kicker"><LockKeyhole size={14} /> PRIVATE BY DESIGN</span>
          <h1>Your documents.<br />Your rules.</h1>
          <p>A calmer, more secure place for the files that matter. Share with confidence and stay in control.</p>
          <div className="story-points">
            <span><Check size={16} /> Private storage from the start</span>
            <span><Check size={16} /> Access you can grant and revoke</span>
            <span><Check size={16} /> A clear record of important activity</span>
          </div>
        </div>
        <div className="story-orbit orbit-one" />
        <div className="story-orbit orbit-two" />
        <div className="story-footer"><span>TRUSTVAULT</span><span>Secure document workspace</span></div>
      </section>

      <section className="auth-side">
        <div className="auth-mobile-brand">
          <span className="brand-mark"><ShieldCheck size={21} /></span>
          <strong>trustvault</strong>
        </div>
        <div className="auth-card">
          <span className="auth-icon"><KeyRound size={21} /></span>
          <p className="eyebrow">{registering ? "START YOUR PRIVATE WORKSPACE" : "WELCOME BACK"}</p>
          <h2>{registering ? "Create your account" : "Sign in to your vault"}</h2>
          <p className="auth-subtitle">{registering ? "A secure home for your important documents." : "Enter your details to access your documents."}</p>
          {notice && <NoticeBanner notice={notice} onDismiss={onDismissNotice} />}
          <form className="auth-form" onSubmit={onSubmit}>
            {registering && (
              <label>
                <span>Full name</span>
                <span className="auth-input-shell">
                  <UserRound size={17} aria-hidden="true" />
                  <input name="name" type="text" placeholder="Your name" autoComplete="name" maxLength={120} required />
                </span>
              </label>
            )}
            <label>
              <span>Email address</span>
              <span className="auth-input-shell">
                <Mail size={17} aria-hidden="true" />
                <input name="email" type="email" placeholder="you@example.com" autoComplete="email" required />
              </span>
            </label>
            <label>
              <span>Password</span>
              <span className="auth-input-shell">
                <KeyRound size={17} aria-hidden="true" />
                <input name="password" type="password" placeholder={registering ? "At least 8 characters" : "Enter your password"} autoComplete={registering ? "new-password" : "current-password"} minLength={registering ? 8 : undefined} required />
              </span>
            </label>
            <button className="button button-auth" type="submit" disabled={loading}>
              {loading ? <span className="spinner spinner-light" /> : null}
              {loading ? (registering ? "Creating account…" : "Signing in…") : (registering ? "Create account" : "Sign in")}
              {!loading && <ArrowRight size={17} />}
            </button>
          </form>
          <div className="auth-switch">
            {registering ? "Already have an account?" : "New to TrustVault?"}
            <button type="button" onClick={() => setMode(registering ? "login" : "register")}>
              {registering ? "Sign in" : "Create an account"}
            </button>
          </div>
          <div className="auth-security"><LockKeyhole size={14} /> Your credentials are sent securely to your TrustVault server.</div>
        </div>
        <div className="auth-bottom">By continuing, you agree to protect your account credentials.</div>
      </section>
    </main>
  );
}

function NoticeBanner({ notice, onDismiss }: { notice: NonNullable<Notice>; onDismiss: () => void }) {
  const success = notice.kind === "success";
  return (
    <div className={`notice notice-${notice.kind}`} role={success ? "status" : "alert"}>
      <span className="notice-symbol">{success ? <Check size={15} /> : <X size={15} />}</span>
      <span>{notice.text}</span>
      <button type="button" onClick={onDismiss} aria-label="Dismiss message"><X size={15} /></button>
    </div>
  );
}
