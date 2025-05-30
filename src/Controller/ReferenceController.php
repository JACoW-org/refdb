<?php

namespace App\Controller;

use App\Entity\Author;
use App\Entity\Conference;
use App\Entity\Feedback;
use App\Entity\Reference;
use App\Form\Type\TagsAsInputType;
use App\Service\DoiService;
use App\Service\FormService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\IsGranted;
use Symfony\Component\Routing\Annotation\Route;

/**
 * Reference controller.
 *
 * @Route("reference")
 */
class ReferenceController extends AbstractController
{
    private $safeRef = "/^((?!\/\/)[a-zA-Z0-9\/._])+$/";

    /**
     * Clear the 'current conference' option
     *
     * @Route("/format", name="conference_format")
     */
    public function formAction(Request $request, FormService $formService)
    {
        if ($request->get('ref') !== null && preg_match($this->safeRef, $request->get('ref'))) {
            $formService->toggleForm();
            return $this->redirect($request->get('ref'));
        }
        return $this->redirectToRoute("homepage");
    }


    /**
     * Creates a new reference entity.
     * @IsGranted("ROLE_ADMIN")
     * @Route("/new/{id}", name="reference_new", defaults={"id": null})
     * @param Request $request
     * @param Conference|null $conference
     * @return \Symfony\Component\HttpFoundation\RedirectResponse|\Symfony\Component\HttpFoundation\Response
     */
    public function newAction(Request $request, Conference $conference = null)
    {
        $reference = new Reference();
        $reference->setConference($conference);
        $form = $this->createForm('App\Form\ReferenceType', $reference);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $em = $this->getDoctrine()->getManager();
            $reference->setCache($reference->__toString());
            $em->persist($reference);
            $em->flush();

            return $this->redirectToRoute('reference_show', array('id' => $reference->getId()));
        }

        return $this->render('reference/new.html.twig', array(
            'reference' => $reference,
            'form' => $form->createView(),
        ));
    }

    /**
     * Finds and displays a reference entity.
     *
     * @Route("/show/{id}", name="reference_show", options={"expose"=true})
     * @param Reference $reference
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function showAction(Reference $reference, FormService $formService, EntityManagerInterface $manager) {
        $warning = "";
        if ($reference->hasTitleIssue()) {
            $warning .= "This papers title is all uppercase, you must correct this before using this reference.\n\n";
        }

        if (empty($reference->getAuthor()) || preg_match_all("/[\[(\/]+/", $reference->getAuthor(), $matches) || count($reference->getAuthors()) == 0) {
            $warning .= "There is a problem with this papers authors.\n\n";
        }
        if (($reference->getConference()->isPublished() && $reference->getInProc() && $reference->getPosition() != "na" && ($reference->getPosition() === null || $reference->getPosition() == "" || $reference->getPosition() == "99-98"))) {
            $warning .= "The page numbers could not be added automatically for this paper. ";
            $warning .= "You must provide the page numbers from the original proceedings which is located at JACoW.org, and substitute ‘pp. XX-XX’ with the correct page numbers.\n";
            $warning .= "* Please report these numbers by clicking on the ‘Fix a problem’ button as an Admin will be able to update this reference for future results.    \n\n";
        }

        $deleteForm = $this->createDeleteForm($reference);
        $form = $formService->getForm() ?? "short";

        $feedbacks = $manager->getRepository(Feedback::class)->findBy(["reference" => $reference->getId(), "resolved" => false]);

        return $this->render('reference/show.html.twig', array(
            'reference' => $reference,
            'warning' => $warning,
            'delete_form' => $deleteForm->createView(),
            'form' => $form,
            'feedbacks' => $feedbacks,
        ));
    }

    /**
     * Generates word reference
     *
     * @Route("/show/{id}/word/{form}", name="reference_word", options={"expose"=true})
     * @param Reference $reference
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function wordAction(Reference $reference, string $form = "short")
    {
        if (!in_array($form, ["short", "long"])) {
            $form = "short";
        }

        return $this->render('reference/word.html.twig', array(
            'reference' => $reference,
            'form' => $form,
        ));
    }

    /**
     * Generates latex reference
     *
     * @Route("/show/{id}/latex", name="reference_latex", options={"expose"=true})
     * @param Reference $reference
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function latexAction(Reference $reference)
    {
        return $this->render('reference/latex.html.twig', array(
            'reference' => $reference
        ));
    }

    /**
     * Generates bibtex reference
     *
     * @Route("/show/{id}/bibtex", name="reference_bibtex", options={"expose"=true})
     * @param Reference $reference
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function bibtexAction(Reference $reference)
    {
        return $this->render('reference/bibtex.html.twig', array(
            'reference' => $reference
        ));
    }

    /**
     * Displays a form to edit an existing reference entity.
     * @IsGranted("ROLE_ADMIN")
     * @Route("/edit/{id}", name="reference_edit")
     */
    public function editAction(Request $request, Reference $reference, DoiService $doiService)
    {

        $manager = $this->getDoctrine()->getManager();
        $deleteForm = $this->createDeleteForm($reference);
        $originalAuthors = clone $reference->getAuthors();
        $originalCustomDoi = (string)$reference->getCustomDoi();

        $editForm = $this->createForm('App\Form\ReferenceType', $reference)
            ->add('authors', TagsAsInputType::class, [
                "entity_class" => Author::class,
                "data_source" => "author_search",
                "label" => "Associated Authors (un-ordered)"]);
        $editForm->handleRequest($request);

        if ($editForm->isSubmitted()) {
            if ($reference->getCustomDoi() !== null && $originalCustomDoi !== $reference->getCustomDoi()) {
                $valid = $doiService->check($reference);
                if (!$valid) {
                    $editForm->addError(new \Symfony\Component\Form\FormError("The DOI you have entered is not valid. Please check and try again."));
                } else {
                    $reference->setDoiVerified(true);
                }
            }

            if ($editForm->isValid()) {
                $newAuthors = $reference->getAuthors();

                /** @var Author $author */
                foreach ($originalAuthors as $author) {
                    if ($newAuthors->contains($author) == false) {
                        $linkedAuthor = $manager->getRepository(Author::class)->find($author->getId());
                        $linkedAuthor->removeReference($reference);
                    }
                }

                /** @var Author $author */
                foreach ($newAuthors as $author) {
                    if ($originalAuthors->contains($author) == false) {
                        $author->addReference($reference);
                        $manager->persist($author);
                    }
                }

                $reference->setCache($reference->__toString());
                $manager->flush();

                return $this->redirectToRoute('reference_show', array('id' => $reference->getId()));
            }
        }

        return $this->render('reference/edit.html.twig', array(
            'reference' => $reference,
            'edit_form' => $editForm->createView(),
            'delete_form' => $deleteForm->createView(),
        ));
    }

    /**
     * Deletes a reference entity.
     * @IsGranted("ROLE_ADMIN")
     * @Route("/delete/{id}", name="reference_delete")
     */
    public function deleteAction(Request $request, Reference $reference)
    {
        $form = $this->createDeleteForm($reference);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $em = $this->getDoctrine()->getManager();
            $em->remove($reference);
            $em->flush();
            return new JsonResponse([
                "success" => true,
                "redirect" => $this->generateUrl("homepage")]);
        }

        return $this->render("reference/delete.html.twig", array("delete_form" => $form->createView()));
    }


    /**
     * Creates a form to delete a reference entity.
     *
     * @param Reference $reference The reference entity
     *
     * @return \Symfony\Component\Form\FormInterface
     */
    private function createDeleteForm(Reference $reference)
    {
        return $this->createFormBuilder()
            ->setAction($this->generateUrl('reference_delete', array('id' => $reference->getId())))
            ->setMethod('DELETE')
            ->getForm();
    }
}
