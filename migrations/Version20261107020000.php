<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Databases that started on FOSUserBundle differ from the initial migration:
 * roles are PHP-serialized and the canonical columns are required. Every step
 * here is a no-op on a database created from the initial migration.
 */
final class Version20261107020000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Convert FOSUserBundle users to the current user schema';
    }

    public function isTransactional(): bool
    {
        // MySQL commits implicitly on DDL; every step is safe to run again.
        return false;
    }

    public function up(Schema $schema): void
    {
        $rows = $this->connection->fetchAllAssociative("SELECT id, roles FROM fos_user WHERE roles LIKE 'a:%'");

        foreach ($rows as $row) {
            $roles = @unserialize($row['roles'], ['allowed_classes' => false]);
            $this->abortIf(!\is_array($roles), \sprintf('fos_user %d has unreadable roles.', $row['id']));

            $this->addSql('UPDATE fos_user SET roles = :roles WHERE id = :id', [
                'roles' => json_encode(array_values($roles), \JSON_THROW_ON_ERROR),
                'id' => $row['id'],
            ]);
        }

        $columns = $this->connection->createSchemaManager()->listTableColumns('fos_user');

        foreach (['username_canonical', 'email_canonical'] as $column) {
            if (isset($columns[$column])) {
                $this->addSql(\sprintf('ALTER TABLE fos_user MODIFY %s VARCHAR(180) DEFAULT NULL', $column));
            }
        }

        // Only exists on databases created from the initial migration.
        $this->addSql('DROP TABLE IF EXISTS reset_password_request');
    }

    public function down(Schema $schema): void
    {
        // Nothing to undo: the current code cannot read serialized roles.
    }
}
