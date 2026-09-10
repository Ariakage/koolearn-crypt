libdecrypt = require('./build/Release/decrypt.node');

module.exports.decrypt = function (data, key, token, expires) {
    return libdecrypt.decrypt(data, key, token, expires);
};