module botan.utils.mixins;

// imitate structs
// todo: Manual Memory Management
mixin template USE_STRUCT_INIT() 
{
	static typeof(this) opCall(T...)(T args) {
		return new typeof(this)(args);
	}
}