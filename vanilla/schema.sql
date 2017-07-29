create table if not exists users (
  uid integer primary key autoincrement,
  username text not null
);

create table if not exists vendors (
  vid integer primary key autoincrement,
  vendorname text not null
);