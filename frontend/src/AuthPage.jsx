import { useState } from "react";
import { Activity, ArrowRight, Cloud, Eye, EyeOff, ShieldCheck } from "lucide-react";
import { apiRequest } from "./api";

export function AuthPage({ onAuthenticated }) {
  const [isRegistering, setIsRegistering] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");
    setBusy(true);
    const form = new FormData(event.currentTarget);
    const email = String(form.get("email")).trim();
    const password = String(form.get("password"));
    try {
      if (isRegistering) {
        await apiRequest("/auth/register", {
          method: "POST",
          body: JSON.stringify({
            email,
            full_name: String(form.get("full_name")).trim(),
            password,
          }),
        });
      }
      const { access_token: token } = await apiRequest("/auth/login", {
        method: "POST",
        body: JSON.stringify({ email, password }),
      });
      onAuthenticated(token);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="auth-shell">
      <section className="auth-story">
        <div className="brand-lockup">
          <span className="brand-mark"><Cloud size={22} strokeWidth={2.2} /></span>
          <span>cloud<span className="brand-accent">bridge</span></span>
        </div>
        <div className="story-copy">
          <div className="eyebrow"><span className="pulse-dot" /> CLOUD OPERATIONS PLATFORM</div>
          <h1>Clarity for every<br /><span>cloud decision.</span></h1>
          <p>One calm, connected view of your infrastructure, security posture, and operations.</p>
        </div>
        <div className="story-metrics">
          <div><Activity size={17} /><span>Infrastructure visibility</span></div>
          <div><ShieldCheck size={17} /><span>Security in context</span></div>
          <div><Cloud size={17} /><span>Built for every cloud</span></div>
        </div>
        <div className="story-footer">CLOUD OPERATIONS, CONNECTED <span>·</span> 01 / 03</div>
      </section>

      <section className="auth-panel">
        <div className="auth-card">
          <div className="mobile-brand brand-lockup">
            <span className="brand-mark"><Cloud size={22} /></span>
            <span>cloud<span className="brand-accent">bridge</span></span>
          </div>
          <span className="section-kicker">{isRegistering ? "CREATE YOUR WORKSPACE" : "WELCOME BACK"}</span>
          <h2>{isRegistering ? "Start with a clear view." : "Sign in to CloudBridge."}</h2>
          <p className="auth-subtitle">
            {isRegistering ? "Your simulated demo workspace is ready in seconds." : "Your infrastructure overview is waiting."}
          </p>
          {error && <div role="alert" className="error-banner">{error}</div>}
          <form onSubmit={handleSubmit} className="auth-form">
            {isRegistering && (
              <label>
                Full name
                <input name="full_name" type="text" autoComplete="name" minLength="2" maxLength="120" placeholder="Alex Morgan" required />
              </label>
            )}
            <label>
              Work email
              <input name="email" type="email" autoComplete="email" placeholder="you@company.com" required />
            </label>
            <label>
              Password
              <span className="password-field">
                <input name="password" type={showPassword ? "text" : "password"} autoComplete={isRegistering ? "new-password" : "current-password"} minLength={isRegistering ? 12 : 1} maxLength="128" placeholder={isRegistering ? "At least 12 characters" : "Enter your password"} required />
                <button className="password-toggle" type="button" onClick={() => setShowPassword(!showPassword)} aria-label={showPassword ? "Hide password" : "Show password"}>
                  {showPassword ? <EyeOff size={17} /> : <Eye size={17} />}
                </button>
              </span>
            </label>
            <button type="submit" className="primary-button auth-submit" disabled={busy}>
              {busy ? "Please wait…" : isRegistering ? "Create account" : "Sign in"}
              {!busy && <ArrowRight size={17} />}
            </button>
          </form>
          <p className="auth-switch">
            {isRegistering ? "Already have an account?" : "New to CloudBridge?"}{" "}
            <button type="button" onClick={() => { setIsRegistering(!isRegistering); setError(""); }}>
              {isRegistering ? "Sign in" : "Create an account"}
            </button>
          </p>
          <div className="auth-note"><ShieldCheck size={15} /> Your account is protected with secure password hashing.</div>
        </div>
      </section>
    </main>
  );
}
