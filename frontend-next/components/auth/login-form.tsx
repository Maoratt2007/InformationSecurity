"use client";

import { FormEvent, useState } from "react";
import { KeyRound, LogIn } from "lucide-react";
import { useRouter } from "next/navigation";
import { ensureRegistrationKeyBundleUploaded } from "@/lib/crypto/registration";
import { supabase } from "@/lib/supabase/client";
import { upsertSignalProfile } from "@/lib/supabase/profiles";

function getLoginErrorMessage(message: string) {
  const normalizedMessage = message.toLowerCase();

  if (normalizedMessage.includes("email not confirmed")) {
    return "This account exists but the email is not confirmed. Confirm it in Supabase Auth or ask an administrator to confirm it.";
  }

  return message;
}

export function LoginForm() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setIsLoading(true);

    try {
      const { data, error: signInError } = await supabase.auth.signInWithPassword({
        email: email.trim(),
        password,
      });

      if (signInError) {
        console.error(
          "Supabase SignIn Error:",
          signInError.message,
          (signInError as { details?: unknown }).details,
        );
        setError(getLoginErrorMessage(signInError.message));
        return;
      }

      if (data.user?.email) {
        await upsertSignalProfile({
          id: data.user.id,
          email: data.user.email,
          fullName: data.user.user_metadata?.full_name,
        });
      }

      if (data.session?.access_token && data.user?.id) {
        void ensureRegistrationKeyBundleUploaded({
          userId: data.user.id,
          accessToken: data.session.access_token,
        }).catch((uploadError: unknown) => {
          console.warn("Signed in, but the public key bundle could not be uploaded.", uploadError);
        });
      }

      router.push("/chat");
    } catch {
      setError("Could not reach Supabase Auth. Check the project URL, public key, and network connection.");
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <form onSubmit={onSubmit} className="space-y-4 rounded-xl border bg-white p-6 shadow-card">
      <h2 className="text-lg font-semibold text-slate-900">Sign in</h2>
      <div className="space-y-2">
        <label className="text-sm font-medium text-slate-700">Email</label>
        <input
          type="text"
          inputMode="email"
          autoCapitalize="none"
          autoComplete="email"
          value={email}
          onChange={(event) => setEmail(event.target.value)}
          className="w-full rounded-lg border border-slate-300 px-3 py-2 outline-none ring-academy-500 transition focus:ring-2"
          placeholder="name@example.com"
          required
        />
      </div>
      <div className="space-y-2">
        <label className="text-sm font-medium text-slate-700">Password</label>
        <input
          type="password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          className="w-full rounded-lg border border-slate-300 px-3 py-2 outline-none ring-academy-500 transition focus:ring-2"
          placeholder="Your password"
          required
        />
      </div>
      {error ? (
        <p className="flex items-center gap-2 text-sm text-rose-700">
          <KeyRound className="h-4 w-4" />
          {error}
        </p>
      ) : null}
      <button
        type="submit"
        disabled={isLoading}
        className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-academy-700 px-4 py-2 text-sm font-medium text-white hover:bg-academy-900 disabled:opacity-60"
      >
        <LogIn className="h-4 w-4" />
        {isLoading ? "Signing in..." : "Sign in"}
      </button>
    </form>
  );
}
