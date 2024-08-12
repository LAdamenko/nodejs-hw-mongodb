import jwt from 'jsonwebtoken';
import { SMTP, TEMPLATES_DIR } from '../constants/index.js';
import { env } from '../utils/env.js';
import { sendEmail } from '../utils/sendMail.js';
import { randomBytes } from 'crypto';
import bcrypt from 'bcrypt';
import createHttpError from 'http-errors';
import { User } from "../db/models/user.js";
import { ACCESS_TOKEN_TTL, REFRESH_TOKEN_TTL } from '../constants/index.js';
import { Session } from '../db/models/session.js';
import handlebars from 'handlebars';
import path from 'node:path';
import fs from 'node:fs/promises';


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

  export const requestResetToken = async (email) => {
    try {
    const user = await User.findOne({ email });
    if (user === null) {
      throw createHttpError(404, 'User not found');
    }

    const resetToken = jwt.sign(
      {
        sub: user._id,
        email,
      },
      env('JWT_SECRET'),
      {
        expiresIn: '5m',
      },
    );
    const resetPasswordTemplatePath = path.join(
      TEMPLATES_DIR,
      'reset-password-email.html',
    );

    const templateSource = (
      await fs.readFile(resetPasswordTemplatePath)
    ).toString();

    const template = handlebars.compile(templateSource);
    const html = template({
      name: user.name,
      link: `${env('APP_DOMAIN')}/reset-password?token=${resetToken}`,
    });
    await sendEmail({
      from: env(SMTP.FROM),
      to: email,
      subject: 'Reset your password',
      html,
    });
    } catch (error) {
      if (error instanceof Error) {
        throw createHttpError(500, "Failed to send the email, please try again later.");
      }
    }
  };

  export const resetPassword = async (payload) => {
    let entries;

    try {
      entries = jwt.verify(payload.token, env('JWT_SECRET'));
    } catch (err) {
      if (err instanceof Error) throw createHttpError(401, "Token is expired or invalid.");
      throw err;
    }

    const user = await User.findOne({
      email: entries.email,
      _id: entries.sub,
    });

    if (user === null) {
      throw createHttpError(404, 'User not found');
    }

    const encryptedPassword = await bcrypt.hash(payload.password, 10);

    await User.updateOne(
      { _id: user._id },
      { password: encryptedPassword },
    );
  };
