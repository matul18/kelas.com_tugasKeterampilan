import bcrypt from 'bcrypt';
import { createHash } from 'crypto';
import { validationResult, matchedData } from 'express-validator';
import { generateToken, verifyToken } from './tokenHandler.js';
import DB from './dbConnection.js';

const validation_result = validationResult.withDefaults({
  formatter: (error) => error.msg,
});

export const validate = (req, res, next) => {
  const errors = validation_result(req).mapped();
  if (Object.keys(errors).length) {
    return res.status(422).json({
      status: 422,
      errors,
    });
  }
  next();
};

// If email already exists in database
export const fetchUserByEmailOrID = async (data, isEmail = true) => {
  let sql = 'SELECT * FROM `users` WHERE `email`=?';
  if (!isEmail) sql = 'SELECT `id` ,`name`, `email` FROM `users` WHERE `id`=?';
  const [row] = await DB.execute(sql, [data]);
  return row;
};


export default {
  //sign up command
  signup: async (req, res, next) => {
    try {
      const { name, email, password } = matchedData(req);

      const saltRounds = 10;
      // Hash the password
      const hashPassword = await bcrypt.hash(password, saltRounds);

    
      // Store user data in the database
      const [result] = await DB.execute(
        'INSERT INTO `users` (`name`,`email`,`password`) VALUES (?,?,?)',
        [name, email, hashPassword]
      );
      res.status(201).json({
        status: 201,
        message: 'You have been successfully registered.',
        user_id: result.insertId,
      });
    } catch (err) {
      next(err);
    }
  },
//login command
  login: async (req, res, next) => {
    try {
      const { user, password } = req.body;
      const verifyPassword = await bcrypt.compare(password, user.password);
      if (!verifyPassword) {
        return res.status(422).json({
          status: 422,
          message: 'Incorrect password!',
        });
      }

      // Generating Access and Refresh Token
      const access_token = generateToken({ id: user.id });
      const refresh_token = generateToken({ id: user.id }, false);

      const md5Refresh = createHash('md5').update(refresh_token).digest('hex');

      // Storing refresh token in MD5 format
      const [result] = await DB.execute(
        'INSERT INTO `refresh_tokens` (`user_id`,`token`) VALUES (?,?)',
        [user.id, md5Refresh]
      );

      if (!result.affectedRows) {
        throw new Error('Failed to whitelist the refresh token.');
      }
      res.json({
        status: 200,
        access_token,
        refresh_token,
      });
    } catch (err) {
      next(err);
    }
  },

  getUser: async (req, res, next) => {
    try {
      // Verify the access token
      const data = verifyToken(req.headers.access_token);
      if (data?.status) return res.status(data.status).json(data);
      // fetching user by the `id` (column)
      const user = await fetchUserByEmailOrID(data.id, false);
      if (user.length !== 1) {
        return res.status(404).json({
          status: 404,
          message: 'User not found',
        });
      }
      res.json({
        status: 200,
        user: user[0],
      });
    } catch (err) {
      next(err);
    }
  },

  refreshToken: async (req, res, next) => {
    try {
      const refreshToken = req.headers.refresh_token;
      // Verify the refresh token
      const data = verifyToken(refreshToken, false);
      if (data?.status) return res.status(data.status).json(data);

      // Converting refresh token to md5 format
      const md5Refresh = createHash('md5').update(refreshToken).digest('hex');

      // Finding the refresh token in the database
      const [refTokenRow] = await DB.execute(
        'SELECT * from `refresh_tokens` WHERE token=?',
        [md5Refresh]
      );

      if (refTokenRow.length !== 1) {
        return res.json({
          status: 401,
          message: 'Unauthorized: Invalid Refresh Token.',
        });
      }

      // Generating new access and refresh token
      const access_token = generateToken({ id: data.id });
      const refresh_token = generateToken({ id: data.id }, false);

      const newMd5Refresh = createHash('md5')
        .update(refresh_token)
        .digest('hex');

      // Replacing the old refresh token to new refresh token
      const [result] = await DB.execute(
        'UPDATE `refresh_tokens` SET `token`=? WHERE `token`=?',
        [newMd5Refresh, md5Refresh]
      );

      if (!result.affectedRows) {
        throw new Error('Failed to whitelist the Refresh token.');
      }

      res.json({
        status: 200,
        access_token,
        refresh_token,
      });
    } catch (err) {
      next(err);
    }
  },

  addToCart: async (req, res, next) => {
    try {
      // Verify the access token
      const data = verifyToken(req.headers.access_token);
      if (data?.status) return res.status(data.status).json(data);

      // get product_id from request
      const { product_id, qty } = matchedData(req);
      console.log(product_id, qty);

      const [result] = await DB.execute(
        'INSERT INTO `user_product` (user_id, product_id, qty) values (?, ?, ?)',
        [data.id, product_id, qty]
      );

      res.json({
        status: 201,
        message: 'You have successfully added item into a cart',
      });
    } catch (err) {
      next(err);
    }
  },

  getDataCart: async (req, res, next) => {
    try {
      const userId = req.params.user_id;
      const [result] = await DB.execute(
        'SELECT * FROM `user_product` WHERE `user_id`=?',
        [userId]
      );

      res.json({
        status: 200,
        message: 'Successfully get data',
        data: result,
      });
    } catch (err) {
      next(err);
    }
  },

  checkout: async (req, res, next) => {
    try {
      const data = verifyToken(req.headers.access_token);
      if (data?.status) return res.status(data.status).json(data);

      const [result] = await DB.execute(
        `SELECT price * up.qty total_price
        FROM products p 
        JOIN user_product up ON up.product_id = p.id 
        WHERE up.user_id = ?`,
        [data.id]
      );

      res.json({
        status: 200,
        message: `Pembelanjaan dengan jumlah ${result[0].total_price} telah berhasil`,
      });
    } catch (err) {
      next(err);
    }
  },
};
