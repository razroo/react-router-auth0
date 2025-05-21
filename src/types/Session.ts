import type { User } from './User';

export type SessionData = {
  accessToken: string;
  refreshToken?: string;
  user: User;
  redirectCount?: number;
};

export type SessionFlashData = {
  error: string;
};