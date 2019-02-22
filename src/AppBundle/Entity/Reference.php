<?php

namespace AppBundle\Entity;

use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\ORM\Mapping as ORM;

/**
 * Reference
 *
 * @ORM\Table(name="reference")
 * @ORM\Entity(repositoryClass="AppBundle\Repository\ReferenceRepository")
 */
class Reference implements \JsonSerializable
{
    /**
     * @var int
     *
     * @ORM\Column(name="id", type="integer")
     * @ORM\Id
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    private $id;

    /**
     * @var string
     * @ORM\Column(type="string", length=4000, nullable=true)
     */
    private $originalAuthors;

    /**
     * @var string
     * @ORM\Column(type="string", length=255, nullable=true)
     */
    private $paperId;

    /**
     * @var string
     *
     * @ORM\Column(name="full", type="string", length=4000, nullable=true)
     */
    private $override;

    /**
     * @var string
     *
     * @ORM\Column(name="title", type="string", length=2000, nullable=true)
     */
    private $title;

    /**
     * @var string
     *
     * @ORM\Column(name="author", type="string", length=4000, nullable=true)
     */
    private $author;

    /**
     * @ORM\ManyToMany(targetEntity="AppBundle\Entity\Author", mappedBy="references")
     */
    private $authors;

    /**
     * @var Conference
     *
     * @ORM\ManyToOne(targetEntity="AppBundle\Entity\Conference", inversedBy="references")
     */
    private $conference;

    /**
     * @var string
     *
     * @ORM\Column(name="isbn", type="string", length=255, nullable=true)
     */
    private $isbn;


    /**
     * @var string
     *
     * @ORM\Column(name="position", type="string", length=255, nullable=true)
     */
    private $position;

    /**
     * @var bool
     *
     * @ORM\Column(name="in_proc", type="boolean", nullable=true)
     */
    private $inProc;
    /**
     * @var bool
     *
     * @ORM\Column(name="et_al", type="boolean", nullable=true)
     */

    private $etAl;

    /**
     * @var string
     *
     * @ORM\Column(name="cache", type="string", length=4000, nullable=true)
     */
    private $cache;

    /**
     * @var boolean
     *
     * @ORM\Column(type="boolean", nullable=true)
     */
    private $publicSubmission;

    /**
     * @ORM\ManyToOne(targetEntity="AppBundle\Entity\Reference", inversedBy="replacements")
     */
    private $replaces;

    /**
     * @ORM\OneToMany(targetEntity="AppBundle\Entity\Reference", mappedBy="replaces")
     */
    private $replacements;

    /**
     * @var boolean
     *
     * @ORM\Column(type="boolean", nullable=true)
     */
    private $doiVerified;

    /**
     * @var string
     *
     * @ORM\Column(name="url", type="string", length=2000, nullable=true)
     */
    private $url;

    /**
     * Constructor
     */
    public function __construct()
    {
        $this->authors = new ArrayCollection();
    }

    /**
     * Get id
     *
     * @return int
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * Set title
     *
     * @param string $title
     *
     * @return Reference
     */
    public function setTitle($title)
    {
        $this->title = $title;

        return $this;
    }

    /**
     * Get title
     *
     * @return string
     */
    public function getTitle()
    {
        return $this->title;
    }

    /**
     * Set author
     *
     * @param string $author
     *
     * @return Reference
     */
    public function setAuthor($author)
    {
        $this->author = $author;

        return $this;
    }

    /**
     * Get author
     *
     * @return string
     */
    public function getAuthor()
    {
        return $this->author;
    }

    /**
     * Set conference
     *
     * @param string $conference
     *
     * @return Reference
     */
    public function setConference($conference)
    {
        $this->conference = $conference;

        return $this;
    }

    /**
     * Get conference
     *
     * @return Conference
     */
    public function getConference()
    {
        return $this->conference;
    }

    /**
     * Set isbn
     *
     * @param string $isbn
     *
     * @return Reference
     */
    public function setIsbn($isbn)
    {
        $this->isbn = $isbn;

        return $this;
    }

    /**
     * Get isbn
     *
     * @return string
     */
    public function getIsbn()
    {
        return $this->isbn;
    }

    /**
     * Set position
     *
     * @param string $position
     *
     * @return Reference
     */
    public function setPosition($position)
    {
        $this->position = $position;

        return $this;
    }

    /**
     * Get position
     *
     * @return string
     */
    public function getPosition()
    {
        return $this->position;
    }


    /**
     * @return bool
     */
    public function isInProc()
    {
        return $this->inProc;
    }

    /**
     * @param bool $inProc
     */
    public function setInProc($inProc)
    {
        $this->inProc = $inProc;
    }



    /**
     * @return ArrayCollection
     */
    public function getAuthors()
    {
        return $this->authors;
    }

    /**
     * @param ArrayCollection $authors
     */
    public function setAuthors($authors)
    {
        $this->authors = $authors;
    }

    /**
     * @return string
     */
    public function getOverride()
    {
        return $this->override;
    }

    /**
     * @param string $override
     */
    public function setOverride($override)
    {
        $this->override = $override;
    }

    /**
     * @return string
     */
    public function getAuthorStr() {
        $author = $this->getAuthor();
        if ($author === null) {
            $authors = $this->getAuthors();
            if (count($authors) >= 6) {
                return $authors[0] . "<em>et al.</em>";
            } elseif (count($authors) > 0) {
                return implode(", ", $authors);
            }
        }
        return $author;
    }

    public function __toString()
    {
        if ($this->getOverride() !== null) {
            return $this->getOverride();
        } else {
            $output = $this->getTitleSection() . "" . $this->getConferenceSection()  . "," . $this->getPaperSection();

            $doi = $this->doi();

            if ($doi !== false && $this->isDoiVerified()) {
                $output .= ", " . $doi;
            } else {
                $output .= ".";
            }
            return $output;
        }
    }

    public function getConferenceSection() {
        return "<em>" . $this->conference . "</em>, " . $this->conference->getLocation() . ", " . $this->conference->getYear();
    }

    public function getTitleSection() {
        $author = $this->getAuthorStr();
        $title = $this->getTitle();

        if ($this->isInProc() && $this->getConference()->isPublished()) {
            $inProc = "in <em>Proc. </em>";
        } else {
            $inProc = "<em>presented at the </em>";
        }

        return $author . " “" . $title . "” " . $inProc;
    }

    public function doi() {
        if ($this->getConference()->isUseDoi()) {
            return 'https://doi.org/10.18429/JACoW-' . $this->getConference()->getDoiCode() . '-' . $this->getPaperId();
        } else {
            return false;
        }
    }

    public function getPaperSection() {

        $position = "";

        if ($this->getConference()->isPublished()) {
            if ($this->getPosition() !== null) {
                $position = "pp. " . $this->getPosition();
            }
        } else {
            $position = "unpublished";
        }
        $paper = "";
        if ($this->getPaperId() !== null) {
            $paper = " paper " . $this->getPaperId() . ", ";
        }

        return $paper . $position;
    }

    /**
     * @return string
     */
    public function getPaperId()
    {
        return $this->paperId;
    }

    /**
     * @param string $paperId
     */
    public function setPaperId($paperId)
    {
        $this->paperId = $paperId;
    }


    /**
     * Get inProc
     *
     * @return boolean
     */
    public function getInProc()
    {
        return $this->inProc;
    }

    /**
     * Add author
     *
     * @param \AppBundle\Entity\Author $author
     *
     * @return Reference
     */
    public function addAuthor(\AppBundle\Entity\Author $author)
    {
        $this->authors[] = $author;

        return $this;
    }

    /**
     * Remove author
     *
     * @param \AppBundle\Entity\Author $author
     */
    public function removeAuthor(\AppBundle\Entity\Author $author)
    {
        $this->authors->removeElement($author);
    }

    /**
     * Set etAl
     *
     * @param boolean $etAl
     *
     * @return Reference
     */
    public function setEtAl($etAl)
    {
        $this->etAl = $etAl;

        return $this;
    }

    /**
     * Get etAl
     *
     * @return boolean
     */
    public function getEtAl()
    {
        return $this->etAl;
    }

    /**
     * @return mixed
     */
    public function getCache()
    {
        return $this->cache;
    }

    /**
     * @param mixed $cache
     */
    public function setCache($cache)
    {
        $this->cache = $cache;
    }

    public function jsonSerialize()
    {
        return [
            "id" => $this->getId(),
            "name" => $this->getCache()
        ];
    }

    /**
     * Set publicSubmission
     *
     * @param boolean $publicSubmission
     *
     * @return Reference
     */
    public function setPublicSubmission($publicSubmission)
    {
        $this->publicSubmission = $publicSubmission;

        return $this;
    }

    /**
     * Get publicSubmission
     *
     * @return boolean
     */
    public function getPublicSubmission()
    {
        return $this->publicSubmission;
    }

    /**
     * Set replaces
     *
     * @param \AppBundle\Entity\Reference $replaces
     *
     * @return Reference
     */
    public function setReplaces(\AppBundle\Entity\Reference $replaces = null)
    {
        $this->replaces = $replaces;

        return $this;
    }

    /**
     * Get replaces
     *
     * @return \AppBundle\Entity\Reference
     */
    public function getReplaces()
    {
        return $this->replaces;
    }

    /**
     * Add replacement
     *
     * @param \AppBundle\Entity\Reference $replacement
     *
     * @return Reference
     */
    public function addReplacement(\AppBundle\Entity\Reference $replacement)
    {
        $this->replacements[] = $replacement;

        return $this;
    }

    /**
     * Remove replacement
     *
     * @param \AppBundle\Entity\Reference $replacement
     */
    public function removeReplacement(\AppBundle\Entity\Reference $replacement)
    {
        $this->replacements->removeElement($replacement);
    }

    /**
     * Get replacements
     *
     * @return \Doctrine\Common\Collections\Collection
     */
    public function getReplacements()
    {
        return $this->replacements;
    }

    /**
     * @return bool
     */
    public function isDoiVerified()
    {
        return $this->doiVerified;
    }

    /**
     * @param bool $doiVerified
     */
    public function setDoiVerified($doiVerified)
    {
        $this->doiVerified = $doiVerified;
    }

    /**
     * @return string
     */
    public function getUrl()
    {
        return $this->url;
    }

    /**
     * @param string $url
     */
    public function setUrl($url)
    {
        $this->url = $url;
    }

    /**
     * @return string
     */
    public function getOriginalAuthors()
    {
        return $this->originalAuthors;
    }

    /**
     * @param string $originalAuthors
     */
    public function setOriginalAuthors($originalAuthors)
    {
        $this->originalAuthors = $originalAuthors;
    }
}
