import dotenv from 'dotenv';
import { createCookieSessionStorage } from 'react-router';
import type { SessionData, SessionFlashData } from '../types/Session';

dotenv.config();

import { environment } from '../config/environment';
if (!environment.sessionSecret) throw new Error('Missing session secret.');

const { getSession, commitSession, destroySession } = createCookieSessionStorage<SessionData, SessionFlashData>({
  cookie: {
    name: '__session',
    httpOnly: true,
    maxAge: 60 * 60 * 24 * 7,
    path: '/',
    sameSite: 'lax',
    secrets: [environment.sessionSecret],
    secure: process.env.NODE_ENV === 'production',
  },
});

export { commitSession, destroySession, getSession };