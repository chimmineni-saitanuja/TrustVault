import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import {
  ArrowDownToLine,
  ArrowRight,
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
  Plus,
  Search,
  ShieldCheck,
  Share2,
  Trash2,
  UserRound,
  X,
} from "lucide-react";

import { api, ApiError, type DocumentRecord, type DocumentShare, type SharePermission, type SharedDocumentRecord, type UserProfile } from "./api";

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
  const [authMode, setAuthMode] = useState<AuthMode>("login");
  const [authLoading, setAuthLoading] = useState(false);
  const [sessionLoading, setSessionLoading] = useState(Boolean(token));
  const [documentsLoading, setDocumentsLoading] = useState(false);
  const [sharedLoading, setSharedLoading] = useState(Boolean(token));
  const [sharedError, setSharedError] = useState<string | null>(null);
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

  useEffect(() => {
    if (!token) {
      setSessionLoading(false);
      setSharedLoading(false);
      return;
    }

    let active = true;
    const restoreSession = async () => {
      try {
        const profile = await api.me(token);
        if (!active) return;
        setUser(profile);
        const rows = await api.documents(token);
        if (active) setDocuments(rows);
        await refreshSharedDocuments(token);
      } catch (error) {
        if (!active) return;
        if (error instanceof ApiError && error.status === 401) {
          clearSession();
          setNotice({ kind: "error", text: "Your session has expired. Sign in again to continue." });
        } else {
          setNotice({ kind: "error", text: messageFromError(error) });
        }
      } finally {
        if (active) setSessionLoading(false);
      }
    };

    void restoreSession();
    return () => {
      active = false;
    };
  }, [token, clearSession, refreshSharedDocuments]);

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
    } catch (error) {
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
    } catch (error) {
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
    setShareBusy(true);
    setNotice(null);
    try {
      const share = await api.grantShare(token, documentId, id, permission);
      setShareRows((current) => ({
        ...current,
        [documentId]: [share, ...(current[documentId] ?? [])],
      }));
      setRecipientId("");
      setNotice({ kind: "success", text: `Access granted with ${permission} permission.` });
    } catch (error) {
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
    } catch (error) {
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
    } catch (error) {
      reportRequestError(error);
    } finally {
      setDownloadingId(null);
    }
  }

  async function previewDocument(document: Pick<DocumentRecord, "id">) {
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
    } catch (error) {
      previewTab.close();
      reportRequestError(error);
    } finally {
      setPreviewingId(null);
    }
  }

  if (sessionLoading) {
    return (
      <main className="boot-screen" aria-live="polite">
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
                        </span>
                      </div>
                      <span className="document-size">{formatBytes(document.file_size)}</span>
                      <span className="document-date">{formatDate(document.created_at)}</span>
                      <div className="document-actions">
                        <button
                          className="button button-quiet"
                          onClick={() => void toggleShares(document.id)}
                          aria-expanded={shareTarget === document.id}
                          aria-controls={`shares-${document.id}`}
                        >
                          <Share2 size={15} /> Share <ChevronDown size={14} className={shareTarget === document.id ? "chevron-open" : ""} />
                        </button>
                        <button
                          className="icon-button download-button"
                          onClick={() => void downloadDocument(document)}
                          disabled={downloadingId === document.id}
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
                          <button className="button button-dark" type="submit" disabled={shareBusy}>
                            <Plus size={16} /> Grant access
                          </button>
                        </form>
                        <p className="share-hint">The backend currently requires a recipient’s user ID. Recipients see shared documents in their Shared with me section.</p>

                        <div className="share-list">
                          {sharesLoading ? (
                            <div className="share-loading"><span className="spinner spinner-small" /> Loading access list…</div>
                          ) : (shareRows[document.id] ?? []).length === 0 ? (
                            <p className="no-shares">No one else has access to this document yet.</p>
                          ) : (
                            (shareRows[document.id] ?? []).map((share) => (
                              <div className={`share-row ${share.is_revoked ? "share-revoked" : ""}`} key={share.id}>
                                <span className="avatar avatar-share">{share.grantee_name.slice(0, 1).toUpperCase()}</span>
                                <span className="share-person"><strong>{share.grantee_name}</strong><small>{share.grantee_email}</small></span>
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
                onClick={() => void refreshSharedDocuments(token)}
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
                  onClick={() => void refreshSharedDocuments(token)}
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
                        {document.permissions.map((grantedPermission) => (
                          <span
                            className={`permission-badge permission-${grantedPermission}`}
                            key={grantedPermission}
                          >
                            {grantedPermission}
                          </span>
                        ))}
                        {(document.permissions.includes("view") ||
                          document.permissions.includes("download")) && (
                          <button
                            className="icon-button download-button"
                            onClick={() => void previewDocument({ id: document.id })}
                            disabled={previewingId === document.id}
                            aria-label={`View ${document.filename}`}
                            title="View"
                          >
                            {previewingId === document.id
                              ? <span className="spinner spinner-small" />
                              : <Eye size={18} />}
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

          <footer className="page-footer">
            <span><ShieldCheck size={15} /> Protected by TrustVault</span>
            <span>Files are private until you grant access.</span>
          </footer>
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
  return (
    <main className="auth-layout">
      <section className="auth-story">
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
                <input name="name" type="text" placeholder="Your name" autoComplete="name" maxLength={120} required />
              </label>
            )}
            <label>
              <span>Email address</span>
              <input name="email" type="email" placeholder="you@example.com" autoComplete="email" required />
            </label>
            <label>
              <span>Password</span>
              <input name="password" type="password" placeholder={registering ? "At least 8 characters" : "Enter your password"} autoComplete={registering ? "new-password" : "current-password"} minLength={registering ? 8 : undefined} required />
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
