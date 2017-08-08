create table if not exists users (
	uid integer primary key autoincrement,
	password text not null,
	email text not null
);

create table if not exists vendors (
	vid integer primary key autoincrement,
	vendorName text not null,
	displayName text not null,
	password text not null,
	email text not null
);

create table if not exists items (
	iid integer primary key autoincrement,
	itemName text not null,
	description text not null,
	vendor text not null,
	price text,
	pathToImg text not null
);