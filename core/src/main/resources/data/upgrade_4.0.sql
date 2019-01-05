ALTER TABLE cpeEntry ADD COLUMN part CHAR(1);
UPDATE cpeEntry SET part='a';

UPDATE Properties SET value='4.1' WHERE ID='version';
