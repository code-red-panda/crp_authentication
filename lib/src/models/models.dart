class UserModel {
  final String id;
  final String email;
  final String? name;
  final String? photo;

  const UserModel({
    required this.id,
    required this.email,
    this.name,
    this.photo,
  });

  /// Empty user which represents an unauthenticated user.
  static const empty = UserModel(
    id: '',
    email: '',
  );

  /// Convenience getter to determine whether the current user is empty.
  bool get isEmpty => this == UserModel.empty;

  /// Convenience getter to determine whether the current user is not empty.
  bool get isNotEmpty => this != UserModel.empty;

  List<Object?> get props => [id, email, name, photo];
}
