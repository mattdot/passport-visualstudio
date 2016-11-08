// Load modules.
var Strategy = require('./strategy');
var InternalOAuthError = require('passport-oauth2').InternalOAuthError;
var AuthorizationError = require('passport-oauth2').AuthorizationError;
var TokenError = require('passport-oauth2').TokenError;

// Expose Strategy.
exports = module.exports = Strategy;

// Exports.
exports.Strategy = Strategy;

exports.AuthorizationError = AuthorizationError;
exports.TokenError = TokenError;
exports.InternalOAuthError = InternalOAuthError;