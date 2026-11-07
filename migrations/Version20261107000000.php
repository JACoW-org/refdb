<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

final class Version20261107000000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Link users to their Indico account';
    }

    public function up(Schema $schema): void
    {
        $this->addSql('ALTER TABLE fos_user ADD indico_id INT DEFAULT NULL');
        $this->addSql('CREATE UNIQUE INDEX UNIQ_957A6479A77D5156 ON fos_user (indico_id)');
    }

    public function down(Schema $schema): void
    {
        $this->addSql('DROP INDEX UNIQ_957A6479A77D5156 ON fos_user');
        $this->addSql('ALTER TABLE fos_user DROP indico_id');
    }
}
