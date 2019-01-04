#ifndef ____COPY_FROM_USER_LOG_H
#define ____COPY_FROM_USER_LOG_H

struct test_struct;
#define copy_from_user_check_type(to, from, n) \
	_Generic(to,							   \
			 struct test_struct *: true,	   \
			 default: false)

#endif /* ____COPY_FROM_USER_LOG_H */
