create table if not exists users (
  uid integer primary key autoincrement,
  password text not null,
  email text not null
);

create table if not exists vendors (
  vid integer primary key autoincrement,
  vendorname text not null,
  password text not null,
  email text not null
);