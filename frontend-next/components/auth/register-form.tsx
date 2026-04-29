"use client";

import { FormEvent, useState } from "react";
import { UserPlus } from "lucide-react";
import { useRouter } from "next/navigation";
import { supabase } from "@/lib/supabase/client";
import { upsertSignalProfile } from "@/lib/supabase/profiles";

function getRegistrationErrorMessage(message: string) {
  const normalizedMessage = message.toLowerCase();

  if (normalizedMessage.includes("rate limit")) {
    return "Supabase is temporarily limiting new registration emails. Please wait a few minutes and try again, or ask an administrator to create the account.";
  }

  if (normalizedMessage.includes("invalid")) {
    return "Supabase rejected this email address. Use a real reachable email address from any provider.";
  }

  return message;
}

export function RegisterForm() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [fullName, setFullName] = useState("");
  const [status, setStatus] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setStatus(null);
    setIsLoading(true);

    try {
      const { data, error } = await supabase.auth.signUp({
        email: email.trim().toLowerCase(),
        password,
        options: {
          data: {
            full_name: fullName.trim(),
          },
        },
      });

      if (error) {
        setStatus(getRegistrationErrorMessage(error.message));
        return;
      }

      if (data.user?.email) {
        await upsertSignalProfile({
          id: data.user.id,
          email: data.user.email,
          fullName,
        });
      }

      if (data.session) {
        router.push("/chat");
        return;
      }

      setStatus("Registration complete. Check your email to verify your account before signing in.");
    } catch {
      setStatus("Could not reach Supabase Auth. Check the project URL, public key, and network connection.");
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <form onSubmit={onSubmit} className="space-y-4 rounded-xl border bg-white p-6 shadow-card">
      <h2 className="text-lg font-semibold text-slate-900">Register</h2>
      <div className="space-y-2">
        <label className="text-sm font-medium text-slate-700">Full name</label>
        <input
          type="text"
          value={fullName}
          onChange={(event) => setFullName(event.target.value)}
          className="w-full rounded-lg border border-slate-300 px-3 py-2 outline-none ring-academy-500 transition focus:ring-2"
          placeholder="First and last name"
          required
        />
      </div>
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
          placeholder="At least 8 characters"
          required
        />
      </div>
      {status ? <p className="text-sm text-slate-600">{status}</p> : null}
      <button
        type="submit"
        disabled={isLoading}
        className="inline-flex w-full items-center justify-center gap-2 rounded-lg border border-academy-700 bg-academy-50 px-4 py-2 text-sm font-medium text-academy-900 hover:bg-academy-100 disabled:opacity-60"
      >
        <UserPlus className="h-4 w-4" />
        {isLoading ? "Creating account..." : "Create account"}
      </button>
    </form>
  );
}
