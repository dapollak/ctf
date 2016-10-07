#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <unistd.h>


constexpr size_t entry_len = 0x50;

void strip_newline(char *buf, size_t size) {
	char *p = &size[buf];
	while (p >= buf) {
		if (0 == *p or '\n' == *p) {
			*p = 0;
		}
		p--;
	}
}


class User {
public:
	User() {}
	User(const char *name, const char *passwd) {
		strncpy(this->name, name, sizeof(this->name));
		strncpy(this->password, passwd, sizeof(this->password));
	}

	bool check_name(const char *name) {
		return 0 == strcmp(this->name, name);
	}

	bool check_password(const char *passwd) {
		return 0 == strcmp(this->password, passwd);
	}

	void read_name() {
		char input[entry_len];
		fgets(input, sizeof(input) - 1, stdin);
		strip_newline(input, sizeof(input));
		memcpy(this->name, input, sizeof(this->name));
	}

	void read_password() {
		char input[entry_len];
		fgets(input, sizeof(input) - 1, stdin);
		strip_newline(input, sizeof(input));
		memcpy(this->password, input, sizeof(this->password));
	}

	virtual const char *get_password() {
		return this->password;
	}

	virtual void shell() {
		printf("no shell for you!\n");
	}

	bool operator ==(const User &other) {
		return (this->check_name(other.name)
		        and this->check_password(other.password));
	}

private:
	char name[entry_len];
	char password[entry_len];
};

class Noob : public User {
public:
	virtual void shell() {
		printf("ehehehe..!");
	}

	bool check_password(const char *) {
		printf("noobs need no passwords!\n");
		return false;
	}
};

class Admin : public User {
public:
	Admin(const char *name, const char *passwd)
		:
		User{name, passwd} {}

	virtual void shell() {
		printf("Hi admin!\n");
		system("/bin/sh");
	}
};

auto password_checker(void (*accepted)()) {
	constexpr ssize_t equals = 0;
	return [&](const char *input, const char *password) {
		char buf[entry_len];
		if (equals == strcmp(input, password)) {
			snprintf(buf, sizeof(buf), "password accepted: %s\n", buf);
			puts(buf);
			accepted();
		} else {
			printf("nope!\n");
		}
	};
}


User login;

int main() {
	setbuf(stdout, nullptr);

	char access_password[entry_len] = "todo: ldap and kerberos support";

	Admin admin{"admin", access_password};

	auto success = [] {
		printf("congrats!\n");
		login.shell();
	};

	printf("please enter your username: ");
	login.read_name();

	printf("please enter your password: ");
	auto check_pw = password_checker(success);
	login.read_password();

	check_pw(login.get_password(), admin.get_password());
}
