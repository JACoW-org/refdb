<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

final class Version20261107010000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Remove password authentication; down() restores the schema but not the password hashes';
    }

    public function up(Schema $schema): void
    {
        $this->addSql('ALTER TABLE fos_user DROP password');
    }

    public function down(Schema $schema): void
    {
        $this->addSql("ALTER TABLE fos_user ADD password VARCHAR(255) DEFAULT '' NOT NULL");
    }
}
