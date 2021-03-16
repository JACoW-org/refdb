<?php

namespace App\Repository;

use Doctrine\ORM\EntityRepository;

/**
 * ConferenceRepository
 *
 * This class was generated by the Doctrine ORM. Add your own custom
 * repository methods below.
 */
class ConferenceRepository extends EntityRepository
{
    public function findEmpty() {
        $em = $this->getEntityManager();
        $query = $em->createQuery("SELECT c FROM App:Conference c WHERE 0 = (SELECT count(r) FROM App:Reference r WHERE c = r.conference)");

        return $query->getResult();
    }

    public function search($term, $type) {
        $query = $this->createQueryBuilder("c");

        if ($type == "date") {
            $query
                ->where("LOWER(c.year) LIKE :query")
                ->setParameter("query", "%" . mb_strtolower($term) . "%");
        } elseif ($type == "location") {
            $query
                ->where("LOWER(c.location) LIKE :query")
                ->setParameter("query", "%" . mb_strtolower($term) . "%");
        } else {
            $query
                ->where("LOWER(c.name) LIKE :query")
                ->orWhere("LOWER(c.code) LIKE :code")
                ->setParameter("query", "%" . mb_strtolower($term) . "%")
                ->setParameter("code", "" . mb_strtolower($term) . "%");
        }

        return $query
            ->orderBy("c.code", "DESC")
            ->setMaxResults(20)
            ->getQuery()
            ->getResult();
    }
}