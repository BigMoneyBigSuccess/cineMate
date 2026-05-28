import { FormEvent, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { login } from '../api/auth';
import { getApiErrorMessage } from '../api/client';
import { saveToken } from '../auth/tokenStorage';
import AuthCard from '../components/AuthCard';

interface FieldErrors {
  email?: string;
  password?: string;
}

export default function LoginPage() {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({});
  const [formError, setFormError] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError('');

    const nextErrors: FieldErrors = {};
    const normalizedEmail = email.trim();
    if (!normalizedEmail) {
      nextErrors.email = 'Введите email.';
    } else if (!/^\S+@\S+\.\S+$/.test(normalizedEmail)) {
      nextErrors.email = 'Введите корректный email.';
    }
    if (!password) {
      nextErrors.password = 'Введите пароль.';
    }
    if (nextErrors.email || nextErrors.password) {
      setFieldErrors(nextErrors);
      return;
    }

    setLoading(true);
    try {
      const response = await login({ email: normalizedEmail, password });
      if (!response.token) {
        setFormError('Не удалось войти. Попробуйте позже.');
        return;
      }
      saveToken(response.token);
      navigate('/');
    } catch (error) {
      setFormError(getApiErrorMessage(error, 'login'));
    } finally {
      setLoading(false);
    }
  }

  return (
    <AuthCard
      title="Вход"
      subtitle="Мы знали, что вы еще вернетесь."
      footer={
        <>
          Нет аккаунта? <Link to="/register">Зарегистрироваться</Link>
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
            autoComplete="current-password"
            value={password}
            onChange={(event) => {
              setPassword(event.target.value);
              setFieldErrors((current) => ({ ...current, password: undefined }));
            }}
            aria-invalid={Boolean(fieldErrors.password)}
            placeholder="Введите пароль"
          />
          {fieldErrors.password ? <small>{fieldErrors.password}</small> : null}
        </label>

        {formError ? <p className="form-error">{formError}</p> : null}

        <button className="primary-button" type="submit" disabled={loading}>
          {loading ? 'Входим...' : 'Войти'}
        </button>
      </form>
    </AuthCard>
  );
}
