create table if not exists users (
	uid integer primary key autoincrement,
	password text not null,
	email text not null
);

create table if not exists vendors (
	vid integer primary key autoincrement,
	vendorName text not null,
	displayName text not null,
	password text,
	email text,
	type_1 text, 
	type_2 text, 
	type_3 text,
	loc text,
	shipping text,
	category text
);

create table if not exists items (
	iid integer primary key autoincrement,
	itemName text not null,
	description text,
	vendor text not null,
	price text,
	pathToImg text
);

create table if not exists drops (
	tid integer primary key autoincrement,
	dropVendor text not null,
	dropDate datetime not null
);