import { randomBytes } from 'crypto';
import bcrypt from 'bcrypt';
import createHttpError from 'http-errors';
import { User } from "../db/models/user.js";
import { ACCESS_TOKEN_TTL, REFRESH_TOKEN_TTL } from '../constants/index.js';
import { Session } from '../db/models/session.js';

export const registerUser = async (payload) => {
    const user = await User.findOne({ email: payload.email });
    if (user !== null) {
        throw createHttpError(409, 'Email already in use');
      }
    const encryptedPassword = await bcrypt.hash(payload.password, 10);
    return await User.create({
        ...payload,
        password: encryptedPassword,
      });
  };

  export const loginUser = async (payload) => {
    const user = await User.findOne({ email: payload.email });
    if (user === null) {
      throw createHttpError(404, 'User not found');
    }
    const isEqual = await bcrypt.compare(payload.password, user.password);

    if (!isEqual) {
      throw createHttpError(401, 'Unauthorized');
    }

    await Session.deleteOne({ userId: user._id });

  const accessToken = randomBytes(30).toString('base64');
  const refreshToken = randomBytes(30).toString('base64');

  return await Session.create({
    userId: user._id,
    accessToken,
    refreshToken,
    accessTokenValidUntil: new Date(Date.now() + ACCESS_TOKEN_TTL),
    refreshTokenValidUntil: new Date(Date.now() + REFRESH_TOKEN_TTL),
  });
  };

  export const refreshUsersSession = async ({ sessionId, refreshToken }) => {
    const session = await Session.findOne({
      _id: sessionId,
      refreshToken,
    });

    if (session === null) {
      throw createHttpError(401, 'Session not found');
    }

    if (new Date() > new Date(session.refreshTokenValidUntil)) {
      throw createHttpError(401, 'Refresh token is expired');
    }

    await Session.deleteOne({ _id: session._Id});

    return await Session.create({
      userId: session.userId,
      accessToken: randomBytes(30).toString('base64'),
      refreshToken: randomBytes(30).toString('base64'),
      accessTokenValidUntil: new Date(Date.now() + ACCESS_TOKEN_TTL),
      refreshTokenValidUntil: new Date(Date.now() + REFRESH_TOKEN_TTL),
    });
  };

  export const logoutUser = async (sessionId) => {
    await Session.deleteOne({ _id: sessionId });
  };
