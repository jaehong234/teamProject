select * from tbl_user;
SELECT * FROM tbl_user LIMIT 10 OFFSET 0;
delete from tbl_user;
delete from tbl_user where id = 8;

UPDATE tbl_user
SET role = 'ROLE_ADMIN' 
WHERE username = 'm001';

select * from tbl_board where id=840;

delete from tbl_board where id=1;


select * from tbl_cate;
select * from tbl_board;
select * from tbl_reply;
select * from tbl_attach;
select * from tbl_evchargerstation where stat_Nm ='서귀포보건소';
select * from tbl_evchargerstation;
select * from tbl_evcharger; 
select count(*) from tbl_evchargerstation;
select count(*) from tbl_evcharger;
select * from maincate;

ALTER TABLE tbl_cate DROP COLUMN id;
ALTER TABLE tbl_cate ADD PRIMARY KEY (cid);


drop table tbl_cate;
drop table tbl_reply_reaction;
drop table tbl_board_reaction;
drop table tbl_attach;
drop table tbl_reply;
drop table tbl_board;
drop table tbl_user;
drop table tbl_evchargerstation;
drop table tbl_evcharger;
drop table tbl_csvdt;
drop table tbl_evstation;
drop table tbl_user_cate_chger_counts;
drop table tbl_chger_counts;

delete from tbl_user;
delete from tbl_reply;
delete from tbl_board;
delete from tbl_evchargerstation;
delete from tbl_evcharger;
delete from maincate;
delete from tbl_cate where cname='전체게시판';

ALTER TABLE tbl_board_attach_entity DROP FOREIGN KEY FKsugd6flygjqiohcnwlfeehtat;

DESCRIBE tbl_evchargerstation;

SELECT * FROM tbl_evchargerstation 
WHERE ('stat_nm' = 'stat_nm' AND stat_nm LIKE '%someValue%') 
   OR ('addr' = 'addr' AND addr LIKE '%someOtherValue%') 
ORDER BY stat_id 
LIMIT 10 OFFSET 0;

ALTER TABLE tbl_reply_reaction
DROP FOREIGN KEY FKtqgqjqidtgmgtvjbtoqo8y13u;
