<?php

namespace AppBundle\Controller;

use AppBundle\Entity\Author;
use AppBundle\Entity\Conference;
use AppBundle\Entity\Reference;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\HttpFoundation\Request;

/**
 * Author controller.
 *
 * @Route("report")
 */
class ReportController extends Controller
{

    /**
     * Lists all author entities.
     * @Route("/", name="report_index")
     */
    public function indexAction(Request $request)
    {
        $manager = $this->getDoctrine()->getManager();
        // missing page numbers

        $references = $manager->getRepository(Reference::class)
            ->createQueryBuilder("r")
            ->select("count(r)")
            ->getQuery()
            ->getSingleScalarResult();

        $conferences = $manager->getRepository(Conference::class)
            ->createQueryBuilder("c")
            ->select("count(c)")
            ->getQuery()
            ->getSingleScalarResult();


        $authors = $manager->getRepository(Author::class)
            ->createQueryBuilder("a")
            ->select("count(a)")
            ->getQuery()
            ->getSingleScalarResult();

        $missingPages = $manager->getRepository(Reference::class)
            ->createQueryBuilder("r")
            ->select("count(r)")
            ->where("r.position = :position")
            ->setParameter("position", "99-99")
            ->getQuery()
            ->getSingleScalarResult();

        // malformed authors
        $authorList = $manager->getRepository(Reference::class)
            ->createQueryBuilder("r")
            ->select("r.id, r.author")
            ->getQuery()
            ->getArrayResult();

        $malformed = 0;
        $malformedIds = [];
        foreach ($authorList as $ref) {
            preg_match_all("/[\[\(\/]+/",$ref['author'], $matches);
            if (count($matches[0]) != 0) {
                $malformedIds[] = $ref['id'];
                $malformed++;
            }
        }


        return $this->render("report/index.html.twig", array(
                "references" => $references,
                "authors" => $authors,
                "conferences" => $conferences,
                "pages" => $missingPages,
                "malformed" => $malformed,
                "malformedIds" => $malformedIds)
        );
    }


    /**
     * Lists all author entities.
     * @Route("/id", name="id_report")
     */
    public function reportAction(Request $request)
    {
        $ids = explode(",", $request->get("filter"));
        $manager = $this->getDoctrine()->getManager();
        $query = $manager->getRepository(Reference::class)
            ->createQueryBuilder("r")
            ->select("r")
            ->where("r.id IN (:ids)")
            ->setParameter("ids", $ids);

        $paginator  = $this->get('knp_paginator');
        $pagination = $paginator->paginate(
            $query,
            $request->query->getInt('page', 1),
            10
        );

        // parameters to template
        return $this->render('report/reference.html.twig', array('pagination' => $pagination));
    }



    /**
     * Lists all author entities.
     * @Route("/pages", name="pages_report")
     */
    public function pagesAction(Request $request)
    {
        $manager = $this->getDoctrine()->getManager();
        $query = $manager->getRepository(Reference::class)
            ->createQueryBuilder("r")
            ->select("r")
            ->where("r.position = :position")
            ->setParameter("position", "99-99");


        $paginator  = $this->get('knp_paginator');
        $pagination = $paginator->paginate(
            $query,
            $request->query->getInt('page', 1),
            10
        );

        // parameters to template
        return $this->render('report/reference.html.twig', array('pagination' => $pagination));
    }

}