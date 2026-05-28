import { FormEvent, useState } from 'react';
import { Link } from 'react-router-dom';
import { register } from '../api/auth';
import { getApiErrorMessage } from '../api/client';
import AuthCard from '../components/AuthCard';

interface FieldErrors {
  email?: string;
  password?: string;
}

export default function RegisterPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({});
  const [formError, setFormError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError('');
    setSuccess('');

    const nextErrors: FieldErrors = {};
    const normalizedEmail = email.trim();
    if (!normalizedEmail) {
      nextErrors.email = 'Введите email.';
    } else if (!/^\S+@\S+\.\S+$/.test(normalizedEmail)) {
      nextErrors.email = 'Введите корректный email.';
    }
    if (!password) {
      nextErrors.password = 'Введите пароль.';
    } else if (password.length < 8) {
      nextErrors.password = 'Минимум 8 символов.';
    }
    if (nextErrors.email || nextErrors.password) {
      setFieldErrors(nextErrors);
      return;
    }

    setLoading(true);
    try {
      await register({ email: normalizedEmail, password });
      setSuccess('Аккаунт создан.');
      setPassword('');
    } catch (error) {
      setFormError(getApiErrorMessage(error, 'register'));
    } finally {
      setLoading(false);
    }
  }

  return (
    <AuthCard
      title="Регистрация"
      subtitle="Узнайте новое о себе и своих друзьях"
      footer={
        <>
          Уже есть аккаунт? <Link to="/login">Войти</Link>
        </>
      }
    >
      <form className="auth-form" onSubmit={handleSubmit} noValidate>
        <label className="form-field" htmlFor="email">
          <span>Email</span>
          <input
            id="email"
            type="email"
            autoComplete="email"
            value={email}
            onChange={(event) => {
              setEmail(event.target.value);
              setFieldErrors((current) => ({ ...current, email: undefined }));
            }}
            aria-invalid={Boolean(fieldErrors.email)}
            placeholder="you@example.com"
          />
          {fieldErrors.email ? <small>{fieldErrors.email}</small> : null}
        </label>

        <label className="form-field" htmlFor="password">
          <span>Пароль</span>
          <input
            id="password"
            type="password"
            autoComplete="new-password"
            value={password}
            onChange={(event) => {
              setPassword(event.target.value);
              setFieldErrors((current) => ({ ...current, password: undefined }));
            }}
            aria-invalid={Boolean(fieldErrors.password)}
            placeholder="Минимум 8 символов"
          />
          {fieldErrors.password ? <small>{fieldErrors.password}</small> : null}
        </label>

        {success ? <p className="form-success">{success}</p> : null}
        {formError ? <p className="form-error">{formError}</p> : null}

        <button className="primary-button" type="submit" disabled={loading}>
          {loading ? 'Создаем...' : 'Создать аккаунт'}
        </button>
      </form>
    </AuthCard>
  );
}
