var db = require('../models')
var bCrypt = require('bcrypt')
var md5 = require('md5')

// ani TEST
const Crypto = require('crypto');

const defaults = {
  IV_SIZE: 12,
  ENCRYPTION_ALGORITHM: 'aes-256-gcm',
  TOKEN_SEPARATOR: '|$|',
};

async function encrypt(plainText, key, {
  IV_SIZE,
  ENCRYPTION_ALGORITHM,
  TOKEN_SEPARATOR,
} = defaults) {
  //const initVector = Crypto.randomBytes(IV_SIZE);
  const initVector = '1f3g41f3g41f3g41f3g4';
  const cipher = Crypto.createCipheriv(ENCRYPTION_ALGORITHM, key, initVector);

  const chunks = [];
  cipher.on('readable', () => {
    const data = cipher.read();
    if (data) chunks.push(data);
  });

  cipher.write(plainText);
  cipher.end();


  const encrypted = await new Promise((res) => {
    cipher.on('end', () => {
      res(Buffer.concat(chunks).toString('base64'));
    });
  });

  const authTag = cipher.getAuthTag().toString('base64');


  return (encrypted + TOKEN_SEPARATOR + initVector.toString('base64') + TOKEN_SEPARATOR + authTag);
}


async function decrypt(token, key, {
  ENCRYPTION_ALGORITHM,
  TOKEN_SEPARATOR,
} = defaults) {
  const [
    payload,
    encodedIV,
    encodedAuthTag,
  ] = token.split(TOKEN_SEPARATOR);

  const initVector = Buffer.from(encodedIV, 'base64');
  const authTag = Buffer.from(encodedAuthTag, 'base64');

  const decipher = Crypto.createDecipheriv(ENCRYPTION_ALGORITHM, key, initVector);

  decipher.setAuthTag(authTag);

  let decrypted = '';

  decipher.on('readable', () => {
    const data = decipher.read();
    if (data) decrypted += data.toString('utf8');
  });

  decipher.write(payload, 'base64');
  decipher.end();

  return new Promise((res) => {
    decipher.on('end', () => {
      res(decrypted);
    });
  });
}






module.exports.isAuthenticated = function (req, res, next) {
	// ani TEST
	const buf = new Buffer([0x62, 0x75, 0x66, 0x66, 0x65, 0x72]);
	
	if (req.isAuthenticated()) {
		req.flash('authenticated', true)
		return next();
	}
	res.redirect('/login');
}

module.exports.isNotAuthenticated = function (req, res, next) {
	if (!req.isAuthenticated())
		return next();
	res.redirect('/learn');
}

module.exports.forgotPw = function (req, res) {
	if (req.body.login) {
		db.User.find({
			where: {
				'login': req.body.login
			}
		}).then(user => {
			if (user) {
				// Send reset link via email happens here
				req.flash('info', 'Check email for reset link')
				res.redirect('/login')
			} else {
				req.flash('danger', "Invalid login username")
				res.redirect('/forgotpw')
			}
		})
	} else {
		req.flash('danger', "Invalid login username")
		res.redirect('/forgotpw')
	}
}

module.exports.resetPw = function (req, res) {
	if (req.query.login) {
		db.User.find({
			where: {
				'login': req.query.login
			}
		}).then(user => {
			if (user) {
				if (req.query.token == md5(req.query.login)) {
					res.render('resetpw', {
						login: req.query.login,
						token: req.query.token
					})
				} else {
					req.flash('danger', "Invalid reset token")
					res.redirect('/forgotpw')
				}
			} else {
				req.flash('danger', "Invalid login username")
				res.redirect('/forgotpw')
			}
		})
	} else {
		req.flash('danger', "Non Existant login username")
		res.redirect('/forgotpw')
	}
}

module.exports.resetPwSubmit = function (req, res) {
	if (req.body.password && req.body.cpassword && req.body.login && req.body.token) {
		if (req.body.password == req.body.cpassword) {
			db.User.find({
				where: {
					'login': req.body.login
				}
			}).then(user => {
				if (user) {
					if (req.body.token == md5(req.body.login)) {
						user.password = bCrypt.hashSync(req.body.password, bCrypt.genSaltSync(10), null)
						user.save().then(function () {
							req.flash('success', "Passowrd successfully reset")
							res.redirect('/login')
						})
					} else {
						req.flash('danger', "Invalid reset token")
						res.redirect('/forgotpw')
					}
				} else {
					req.flash('danger', "Invalid login username")
					res.redirect('/forgotpw')
				}
			})
		} else {
			req.flash('danger', "Passowords do not match")
			res.render('resetpw', {
				login: req.query.login,
				token: req.query.token
			})
		}

	} else {
		req.flash('danger', "Invalid request")
		res.redirect('/forgotpw')
	}
}
