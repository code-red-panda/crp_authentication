import 'dart:async';

import 'package:crp_authentication/crp_authentication.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:firebase_auth/firebase_auth.dart' as firebase_auth;
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:google_sign_in/google_sign_in.dart';
import 'package:meta/meta.dart';

/// Thrown during the sign-up process if a failure occurs.
class SignUpWithEmailAndPasswordFailure implements Exception {
  const SignUpWithEmailAndPasswordFailure([
    this.message = 'An unknown exception occurred.',
  ]);

  /// Create an authentication message
  /// from a firebase authentication exception code.
  /// https://pub.dev/documentation/firebase_auth/latest/firebase_auth/FirebaseAuth/createUserWithEmailAndPassword.html
  factory SignUpWithEmailAndPasswordFailure.fromCode(String code) {
    switch (code) {
      case 'invalid-email':
        return const SignUpWithEmailAndPasswordFailure(
          'Email is not valid or badly formatted.',
        );
      case 'user-disabled':
        return const SignUpWithEmailAndPasswordFailure(
          'This user has been disabled. Please contact support for help.',
        );
      case 'email-already-in-use':
        return const SignUpWithEmailAndPasswordFailure(
          'An account already exists for that email.',
        );
      case 'operation-not-allowed':
        return const SignUpWithEmailAndPasswordFailure(
          'Operation is not allowed.  Please contact support.',
        );
      case 'weak-password':
        return const SignUpWithEmailAndPasswordFailure(
          'Please enter a stronger password.',
        );
      default:
        return const SignUpWithEmailAndPasswordFailure();
    }
  }

  /// The associated error message.
  final String message;
}

/// Thrown during the sign-in process if a failure occurs.
/// https://pub.dev/documentation/firebase_auth/latest/firebase_auth/FirebaseAuth/signInWithEmailAndPassword.html
class SignInWithEmailAndPasswordFailure implements Exception {
  const SignInWithEmailAndPasswordFailure([
    this.message = 'An unknown exception occurred.',
  ]);

  /// Create an authentication message
  /// from a firebase authentication exception code.
  factory SignInWithEmailAndPasswordFailure.fromCode(String code) {
    switch (code) {
      case 'invalid-email':
        return const SignInWithEmailAndPasswordFailure(
          'Email is not valid or badly formatted.',
        );
      case 'user-disabled':
        return const SignInWithEmailAndPasswordFailure(
          'This user has been disabled. Please contact support for help.',
        );
      case 'user-not-found':
        return const SignInWithEmailAndPasswordFailure(
          'Email is not found, please create an account.',
        );
      case 'wrong-password':
        return const SignInWithEmailAndPasswordFailure(
          'Incorrect password, please try again.',
        );
      default:
        return const SignInWithEmailAndPasswordFailure();
    }
  }

  /// The associated error message.
  final String message;
}

/// Thrown during the Google sign-in process if a failure occurs.
/// https://pub.dev/documentation/firebase_auth/latest/firebase_auth/FirebaseAuth/signInWithCredential.html
class SignInWithGoogleFailure implements Exception {
  const SignInWithGoogleFailure([
    this.message = 'An unknown exception occurred.',
  ]);

  /// Create an authentication message
  /// from a firebase authentication exception code.
  factory SignInWithGoogleFailure.fromCode(String code) {
    switch (code) {
      case 'account-exists-with-different-credential':
        return const SignInWithGoogleFailure(
          'Account exists with different credentials.',
        );
      case 'invalid-credential':
        return const SignInWithGoogleFailure(
          'The credential received is malformed or has expired.',
        );
      case 'operation-not-allowed':
        return const SignInWithGoogleFailure(
          'Operation is not allowed.  Please contact support.',
        );
      case 'user-disabled':
        return const SignInWithGoogleFailure(
          'This user has been disabled. Please contact support for help.',
        );
      case 'user-not-found':
        return const SignInWithGoogleFailure(
          'Email is not found, please create an account.',
        );
      case 'wrong-password':
        return const SignInWithGoogleFailure(
          'Incorrect password, please try again.',
        );
      case 'invalid-verification-code':
        return const SignInWithGoogleFailure(
          'The credential verification code received is invalid.',
        );
      case 'invalid-verification-id':
        return const SignInWithGoogleFailure(
          'The credential verification ID received is invalid.',
        );
      default:
        return const SignInWithGoogleFailure();
    }
  }

  /// The associated error message.
  final String message;
}

/// Thrown during the sign-out process if a failure occurs.
class SignOutFailure implements Exception {}

/// Thrown during the reset password email process if a failure occurs.
class SendPasswordResetEmailFailure implements Exception {
  const SendPasswordResetEmailFailure([
    this.message = 'An unknown exception occurred.',
  ]);

  /// Create an authentication message
  /// from a firebase authentication exception code.
  /// https://pub.dev/documentation/firebase_auth/latest/firebase_auth/FirebaseAuth/sendPasswordResetEmail.html
  factory SendPasswordResetEmailFailure.fromCode(String code) {
    switch (code) {
      case 'invalid-email':
        return const SendPasswordResetEmailFailure(
          'Email is not valid or badly formatted.',
        );
      case 'missing-android-pkg-name':
        return const SendPasswordResetEmailFailure(
          'Missing Android package name.',
        );
      case 'missing-continue-uri':
        return const SendPasswordResetEmailFailure(
          'Missing continue URL.',
        );
      case 'missing-ios-bundle-id':
        return const SendPasswordResetEmailFailure(
          'Missing IOS Bundle ID.',
        );
      case 'invalid-continue-uri':
        return const SendPasswordResetEmailFailure(
          'Continue URL is not valid or badly formatted.',
        );
      case 'unauthorized-continue-uri':
        return const SendPasswordResetEmailFailure(
          'Continue URL is not whitelisted in Firebase.',
        );
      case 'user-not-found':
        return const SendPasswordResetEmailFailure(
          'No user found matching this email address.',
        );
      default:
        return const SendPasswordResetEmailFailure();
    }
  }

  /// The associated error message.
  final String message;
}

/// Thrown during the reset password email process if a failure occurs.
class ReAuthenticateFailure implements Exception {
  const ReAuthenticateFailure([
    this.message = 'An unknown exception occurred.',
  ]);

  /// Create an authentication message
  /// from a firebase authentication exception code.
  /// https://pub.dev/documentation/firebase_auth/latest/firebase_auth/User/reauthenticateWithCredential.html
  factory ReAuthenticateFailure.fromCode(String code) {
    switch (code) {
      case 'user-mismatch':
        return const ReAuthenticateFailure(
          'Credential does not match user.',
        );
      case 'user-not-found':
        return const ReAuthenticateFailure(
          'Credential does not match existing user.',
        );
      case 'invalid-credential':
        return const ReAuthenticateFailure(
          'Credential is invalid or expired.',
        );
      case 'invalid-email':
        return const ReAuthenticateFailure(
          'Email is not valid or badly formatted.',
        );
      case 'wrong-password':
        return const ReAuthenticateFailure(
          'Credential is incorrect or this account does not have a password.',
        );
      default:
        return const ReAuthenticateFailure();
    }
  }

  /// The associated error message.
  final String message;
}

/// Thrown during the update email process if a failure occurs.
/// https://pub.dev/documentation/firebase_auth/latest/firebase_auth/User/updateEmail.html
class UpdateEmailFailure implements Exception {
  const UpdateEmailFailure([
    this.message = 'An unknown exception occurred.',
  ]);

  /// Create an authentication message
  /// from a firebase authentication exception code.
  factory UpdateEmailFailure.fromCode(String code) {
    switch (code) {
      case 'invalid-email':
        return const UpdateEmailFailure(
          'Email is not valid or badly formatted.',
        );
      case 'email-already-in-use':
        return const UpdateEmailFailure(
          'Email is already used in another account.',
        );
      case 'requires-recent-login':
        return const UpdateEmailFailure(
          'A recent login is required to complete this operation.',
        );
      default:
        return const UpdateEmailFailure();
    }
  }

  /// The associated error message.
  final String message;
}

/// Thrown during the update password process if a failure occurs.
/// https://pub.dev/documentation/firebase_auth/latest/firebase_auth/User/updatePassword.html
class UpdatePasswordFailure implements Exception {
  const UpdatePasswordFailure([
    this.message = 'An unknown exception occurred.',
  ]);

  /// Create an authentication message
  /// from a firebase authentication exception code.
  factory UpdatePasswordFailure.fromCode(String code) {
    switch (code) {
      case 'weak-password':
        return const UpdatePasswordFailure(
          'Password is not strong enough.',
        );
      case 'requires-recent-login':
        return const UpdatePasswordFailure(
          'A recent login is required to complete this operation.',
        );
      default:
        return const UpdatePasswordFailure();
    }
  }

  /// The associated error message.
  final String message;
}

/// Thrown during the reload process if a failure occurs.
class ReloadFailure implements Exception {}

/// Repository which manages user authentication.
class Authentication {
  Authentication({
    firebase_auth.FirebaseAuth? firebaseAuth,
    GoogleSignIn? googleSignIn,
  })  : _firebaseAuth = firebaseAuth ?? firebase_auth.FirebaseAuth.instance,
        _googleSignIn = googleSignIn ?? GoogleSignIn.standard();

  final firebase_auth.FirebaseAuth _firebaseAuth;
  final GoogleSignIn _googleSignIn;

  /// Whether or not the current environment is web
  /// Should only be overridden for testing purposes. Otherwise,
  /// defaults to [kIsWeb]
  @visibleForTesting
  bool isWeb = kIsWeb;

  /// Stream of [UserModel] which will emit the current user when
  /// the authentication state changes.
  ///
  /// Emits [UserModel.empty] if the user is not authenticated.
  Stream<UserModel> get user {
    return _firebaseAuth.userChanges().map((firebaseUser) {
      final user =
          firebaseUser == null ? UserModel.empty : firebaseUser.toUserModel;
      return user;
    });
  }

  /// Refresh the current user if signed in
  ///
  /// Throws a [ReloadFailure] if an exception occurs.
  Future<void> reload() async {
    try {
      await _firebaseAuth.currentUser?.reload();
    } catch (_) {
      throw ReloadFailure();
    }
  }

  /// Signs up with the provided [email] and [password].
  ///
  /// Throws a [SignUpWithEmailAndPasswordFailure] if an exception occurs.
  Future<void> signUp({
    required String email,
    required String password,
  }) async {
    try {
      await _firebaseAuth.createUserWithEmailAndPassword(
        email: email,
        password: password,
      );
    } on firebase_auth.FirebaseAuthException catch (e) {
      throw SignUpWithEmailAndPasswordFailure.fromCode(e.code);
    } catch (_) {
      throw const SignUpWithEmailAndPasswordFailure();
    }
  }

  /// Starts the Sign In with Google Flow.
  ///
  /// Throws a [SignInWithGoogleFailure] if an exception occurs.
  Future<void> signInWithGoogle() async {
    try {
      late final firebase_auth.AuthCredential credential;
      if (isWeb) {
        final googleProvider = firebase_auth.GoogleAuthProvider();
        final userCredential = await _firebaseAuth.signInWithPopup(
          googleProvider,
        );
        credential = userCredential.credential!;
      } else {
        final googleUser = await _googleSignIn.signIn();
        final googleAuth = await googleUser!.authentication;
        credential = firebase_auth.GoogleAuthProvider.credential(
          accessToken: googleAuth.accessToken,
          idToken: googleAuth.idToken,
        );
      }

      await _firebaseAuth.signInWithCredential(credential);
    } on firebase_auth.FirebaseAuthException catch (e) {
      throw SignInWithGoogleFailure.fromCode(e.code);
    } catch (_) {
      throw const SignInWithGoogleFailure();
    }
  }

  /// Signs in with the provided [email] and [password].
  ///
  /// Throws a [SignInWithEmailAndPasswordFailure] if an exception occurs.
  Future<void> signInWithEmailAndPassword({
    required String email,
    required String password,
  }) async {
    try {
      await _firebaseAuth.signInWithEmailAndPassword(
        email: email,
        password: password,
      );
    } on firebase_auth.FirebaseAuthException catch (e) {
      throw SignInWithEmailAndPasswordFailure.fromCode(e.code);
    } catch (_) {
      throw const SignInWithEmailAndPasswordFailure();
    }
  }

  /// Signs out the current user which will emit
  /// [User.empty] from the [user] Stream.
  ///
  /// Throws a [SignOutFailure] if an exception occurs.
  Future<void> signOut() async {
    try {
      await Future.wait([
        _firebaseAuth.signOut(),
        _googleSignIn.signOut(),
      ]);
    } catch (_) {
      throw SignOutFailure();
    }
  }

  /// Sends a password reset email.
  ///
  /// Throws a [SendPasswordResetEmailFailure] if an exception occurs.
  Future<void> sendPasswordResetEmail({
    required String email,
  }) async {
    try {
      await _firebaseAuth.sendPasswordResetEmail(email: email);
    } on firebase_auth.FirebaseAuthException catch (e) {
      throw SendPasswordResetEmailFailure.fromCode(e.code);
    } catch (_) {
      throw const SendPasswordResetEmailFailure();
    }
  }

  /// Reauthenticate a user with a credential.
  ///
  /// Throws a [ReAuthenticateFailure] if an exception occurs.
  Future<void> reAuthenticate({
    required String email,
    required String password,
  }) async {
    try {
      AuthCredential credential =
          EmailAuthProvider.credential(email: email, password: password);

      await _firebaseAuth.currentUser?.reauthenticateWithCredential(credential);
    } on firebase_auth.FirebaseAuthException catch (e) {
      throw ReAuthenticateFailure.fromCode(e.code);
    } catch (_) {
      throw const ReAuthenticateFailure();
    }
  }

  /// Updates a user's email (a recent login is required).
  ///
  /// Throws a [UpdateEmailFailure] if an exception occurs.
  Future<void> updateEmail({
    required String email,
  }) async {
    try {
      await _firebaseAuth.currentUser?.updateEmail(email);
    } on firebase_auth.FirebaseAuthException catch (e) {
      throw UpdateEmailFailure.fromCode(e.code);
    } catch (_) {
      throw const UpdateEmailFailure();
    }
  }

  /// Updates a user's password (a recent login is required).
  ///
  /// Throws a [UpdatePasswordFailure] if an exception occurs.
  Future<void> updatePassword({
    required String password,
  }) async {
    try {
      await _firebaseAuth.currentUser?.updatePassword(password);
    } on firebase_auth.FirebaseAuthException catch (e) {
      throw UpdatePasswordFailure.fromCode(e.code);
    } catch (_) {
      throw const UpdatePasswordFailure();
    }
  }
}

/// Maps a Firebase Auth User to our UserModel
extension on firebase_auth.User {
  UserModel get toUserModel {
    return UserModel(
      id: uid,
      email: email ?? '',
      name: displayName,
      photo: photoURL,
    );
  }
}
