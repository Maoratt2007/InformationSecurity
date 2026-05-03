import { HomeSessionRedirect } from "@/components/auth/home-session-redirect";
import { LoginForm } from "@/components/auth/login-form";
import { RegisterForm } from "@/components/auth/register-form";

export default function HomePage() {
  return (
    <main className="min-h-screen bg-slate-100 px-4 py-10">
      <HomeSessionRedirect />
      <div className="mx-auto max-w-6xl">
        <header className="mb-8">
          <h1 className="text-3xl font-bold tracking-tight text-slate-900">University Instant Messaging Portal</h1>
          <p className="mt-2 text-sm text-slate-600">
            Foundational secure messaging workspace with Supabase authentication and Signal-oriented key infrastructure.
          </p>
        </header>

        <section className="grid gap-6 lg:grid-cols-2">
          <LoginForm />
          <RegisterForm />
        </section>
      </div>
    </main>
  );
}
