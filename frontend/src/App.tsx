import { Navigate, Route, Routes } from 'react-router-dom';
import AnalyticsPage from './pages/AnalyticsPage';
import CatalogPage from './pages/CatalogPage';
import FriendProfilePage from './pages/FriendProfilePage';
import FriendsPage from './pages/FriendsPage';
import HomePage from './pages/HomePage';
import LoginPage from './pages/LoginPage';
import ProfilePage from './pages/ProfilePage';
import RegisterPage from './pages/RegisterPage';

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<HomePage />} />
      <Route path="/catalog" element={<CatalogPage />} />
      <Route path="/search" element={<CatalogPage />} />
      <Route path="/profile" element={<ProfilePage />} />
      <Route path="/friends" element={<FriendsPage />} />
      <Route path="/users/:userId" element={<FriendProfilePage />} />
      <Route path="/analytics" element={<AnalyticsPage />} />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
