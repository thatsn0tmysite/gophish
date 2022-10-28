
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
ALTER TABLE campaigns ADD COLUMN allowed_cidr text;
ALTER TABLE campaigns ADD COLUMN blocked_cidr text;
ALTER TABLE campaigns ADD COLUMN allowed_countries text;
ALTER TABLE campaigns ADD COLUMN blocked_countries text;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

