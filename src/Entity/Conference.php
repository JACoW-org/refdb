<?php

namespace App\Entity;

use DateTime;
use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Validator\Constraints as Assert;

/**
 * Conference
 *
 * @ORM\Table(name="conference",indexes={@ORM\Index(name="conference_code_idx", columns={"code"})}))
 * @ORM\Entity(repositoryClass="App\Repository\ConferenceRepository")
 */
class Conference implements \JsonSerializable
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
     * @var int
     * Indico event ID
     * @ORM\Column(type="integer", nullable=true)
     */
    private $eventId;

    /**
     * @var string
     * Long version of a conference name.
     * @ORM\Column(name="name", type="string", length=4000, nullable=true)
     */
    private $name;

    /**
     * @var string
     * eg. IPAC'18
     * @ORM\Column(name="code", type="string", length=255)
     */
    private $code;

    /**
     * Start of conference (e.g. 18 March 2018)
     * @var DateTime
     * @ORM\Column(type="date", nullable=true)
     */
    private $conferenceStart;

    /**
     * Last day of conference (e.g. 21 March 2018)
     * @var DateTime
     * @ORM\Column(type="date", nullable=true)
     */
    private ?DateTime $conferenceEnd;
    /**
     * This is the date of the conference, Eg. May 2018
     * @var string
     * @ORM\Column(name="year", type="string", length=255, nullable=true)
     */
    private $year;

    /**
     * @var string
     * eg. International Beam Instrumentation Conference
     * @ORM\Column(name="series", type="string", length=150, nullable=true)
     */
    private $series;

    /**
     * @var int
     * eg. 9
     * @ORM\Column(name="series_number", type="integer", nullable=true)
     */
    private $seriesNumber;
    
    /**
     * eg. 2673-5350 (stored without dashes)
     * @ORM\Column(name="issn", type="string", length=8, nullable=true)
     */
    private $issn;
    
    /**
     * e.g. 978-3-95450-222-6 (stored without dashes)
     * @ORM\Column(name="isbn", type="string", length=13, nullable=true)
     */
    private $isbn;
    
    /**
     * @var int
     * eg. 12
     * @ORM\Column(name="pub_month", type="integer", nullable=true)
     */
    private $pubMonth;
    
    /**
     * @var int
     * eg. 2022
     * @ORM\Column(name="pub_year", type="integer", nullable=true)
     */
    private $pubYear;

    /**
     * Conference component of the DOIs
     * @var string
     *
     * @ORM\Column(type="string", length=255, nullable=true)
     */
    private $doiCode;

    /**
     * Enable DOIs or not.
     * @ORM\Column(type="boolean", nullable=true)
     * @var boolean
     */
    private $useDoi;

    /**
     * @ORM\Column(type="string", nullable=true, length=1000)
     * Path to conference website
     * @var string
     */
    private $baseUrl;

    /**
     * Location of the conference, eg. Sydney, Australia
     * @var string
     * Assert\Regex("/^([A-Za-zàèìòùÀÈÌÒÙáéíóúýÁÉÍÓÚÝâêîôûÂÊÎÔÛãñõÃÑÕäëïöüÿÄËÏÖÜŸçÇßØøÅåÆæœ '\-]+, (?!USA)[A-Za-zàèìòùÀÈÌÒÙáéíóúýÁÉÍÓÚÝâêîôûÂÊÎÔÛãñõÃÑÕäëïöüÿÄËÏÖÜŸçÇßØøÅåÆæœ '\-]+|[A-Za-zàèìòùÀÈÌÒÙáéíóúýÁÉÍÓÚÝâêîôûÂÊÎÔÛãñõÃÑÕäëïöüÿÄËÏÖÜŸçÇßØøÅåÆæœ '\-]+, [A-Za-zàèìòùÀÈÌÒÙáéíóúýÁÉÍÓÚÝâêîôûÂÊÎÔÛãñõÃÑÕäëïöüÿÄËÏÖÜŸçÇßØøÅåÆæœ '\-]+, USA)$/")
     * @ORM\Column(name="location", type="string", length=2000)
     */
    private $location;

    /**
     * @ORM\OneToMany(targetEntity="App\Entity\Reference", mappedBy="conference", cascade={"remove"})
     * @var ArrayCollection
     */
    private $references;

    /**
     * Status of the conference proceedings
     *
     * @var boolean
     *
     * @ORM\Column(type="boolean", nullable=true)
     */
    private $isPublished;

    /**
     * Automatic import URL for unpublished conferences
     * @var string
     *
     * @ORM\Column(type="string", length=2000, nullable=true)
     */
    private $importUrl;

    /**
     * Get id
     *
     * @return int
     */
    public function getId()
    {
        return $this->id;
    }

    public function getEventId(): ?int
    {
        return $this->eventId;
    }

    public function setEventId(?int $eventId): void
    {
        $this->eventId = $eventId;
    }

    /**
     * Set name
     *
     * @param string $name
     *
     * @return Conference
     */
    public function setName($name)
    {
        $this->name = $name;

        return $this;
    }

    /**
     * Get name
     *
     * @return string
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * Set code
     *
     * @param string $code
     *
     * @return Conference
     */
    public function setCode($code)
    {
        $this->code = $code;

        return $this;
    }

    /**
     * Get code
     *
     * @return string
     */
    public function getCode()
    {
        return $this->code;
    }

    /**
     * Set year
     *
     * @param string $year
     *
     * @return Conference
     */
    public function setYear($year)
    {
        $this->year = $year;

        return $this;
    }

    /**
     * Get year
     *
     * @return string
     */
    public function getYear()
    {
        return $this->year;
    }

    /**
     * Set location
     *
     * @param string $location
     *
     * @return Conference
     */
    public function setLocation($location)
    {
        $this->location = $location;

        return $this;
    }

    /**
     * Get location
     *
     * @return string
     */
    public function getLocation()
    {
        return $this->location;
    }

    /**
     * @return ArrayCollection
     */
    public function getReferences()
    {
        return $this->references;
    }

    /**
     * @param ArrayCollection $references
     */
    public function setReferences($references)
    {
        $this->references = $references;
    }

    public function __toString()
    {
        return $this->getForm();
    }

    public function getPlain() {
        return strip_tags($this->__toString());
    }
    /**
     * Constructor
     */
    public function __construct()
    {
        $this->isPublished = false;
        $this->references = new ArrayCollection();
    }

    /**
     * Add reference
     *
     * @param Reference $reference
     *
     * @return Conference
     */
    public function addReference(Reference $reference)
    {
        $this->references[] = $reference;

        return $this;
    }

    /**
     * Remove reference
     *
     * @param Reference $reference
     */
    public function removeReference(Reference $reference)
    {
        $this->references->removeElement($reference);
    }

    /**
     * @return bool
     */
    public function isUseDoi()
    {
        return $this->useDoi;
    }

    /**
     * @param bool $useDoi
     */
    public function setUseDoi($useDoi)
    {
        $this->useDoi = $useDoi;
    }

    /**
     * @return string
     */
    public function getDoiCode()
    {
        return $this->doiCode;
    }

    /**
     * @param string $doiCode
     */
    public function setDoiCode($doiCode)
    {
        $this->doiCode = $doiCode;
    }

    /**
     * @return string
     */
    public function getImportUrl()
    {
        return $this->importUrl;
    }

    /**
     * @param string $importUrl
     */
    public function setImportUrl($importUrl)
    {
        $this->importUrl = $importUrl;
    }

    /**
     * @return bool
     */
    public function isPublished()
    {
        return $this->isPublished;
    }

    /**
     * @param bool $isPublished
     */
    public function setIsPublished($isPublished)
    {
        if ($isPublished === null) {
            $this->isPublished = false;
        } else {
            $this->isPublished = $isPublished;
        }
    }

    public function getForm($form = "long") {
        if ($this->getName() !== null && $form == "long") {
            return $this->getName() . " (" . $this->getCode() . ")";
        } else {
            return $this->getCode();
        }
    }

    public function jsonSerialize(): array
    {
        $start = $this->getConferenceStart();
        $end = $this->getConferenceEnd();
        return [
            "id"=>$this->getId(),
            "eventId"=>$this->getEventId(),
            "name"=> $this->getName(),
            "code" => $this->getCode(),
            "conferenceStart"=> $start ? $this->getConferenceStart()->format("Y-m-d") : null,
            "conferenceEnd"=> $end ? $end->format("Y-m-d") : null,
            "year" => $this->getYear(),
            "series" => $this->getSeries(),
            "seriesNumber" => $this->getSeriesNumber(),
            "issn" => $this->getIssn(),
            "isbn" => $this->getIsbn(),
            "pubYear" => $this->getPubYear(),
            "pubMonth" => $this->getPubMonth(),
            "doiCode" => $this->getDoiCode(),
            "useDoi" => $this->isUseDoi(),
            "baseUrl" => $this->getBaseUrl(),
            "location" => $this->getLocation(),
            "isPublished" => $this->isPublished(),
            "importUrl" => $this->getImportUrl()
        ];
    }

    /**
     * @return string
     */
    public function getBaseUrl()
    {
        return $this->baseUrl;
    }

    /**
     * @param string $basedUrl
     */
    public function setBaseUrl($basedUrl)
    {
        $this->baseUrl = $basedUrl;
    }

    public function getSeries(){
        return $this->series;
    }

    public function setSeries($series){
        $this->series = $series;
    }

    public function getSeriesNumber(){
        return $this->seriesNumber;
    }

    public function setSeriesNumber($seriesNumber){
        $this->seriesNumber = $seriesNumber;
    }

    public function getIssn(){
        return $this->issn;
    }

    public function getIssnFormatted() {
        $issn = $this->getIssn();
        $result = substr($issn, 0, 4) . "-";
        $result .= substr($issn, 4, 8);
        return $result;
    }

    public function setIssn($issn){
        $this->issn = $issn;
    }

    public function getIsbn(){
        return $this->isbn;
    }

    public function getIsbnFormatted() {
        $isbn = $this->getIsbn();
        $result = substr($isbn, 0, 3) . "-";
        $result .= substr($isbn, 3, 1) . "-";
        $result .= substr($isbn, 4, 2) . "-";
        $result .= substr($isbn, 6, 6) . "-";
        $result .= substr($isbn, 12, 1);
        return $result;
    }

    public function setIsbn($isbn){
        $this->isbn = $isbn;
    }

    public function getPubMonth(){
        return $this->pubMonth;
    }

    public function setPubMonth($pubMonth){
        $this->pubMonth = $pubMonth;
    }

    public function getPubYear(){
        return $this->pubYear;
    }

    public function setPubYear($pubYear){
        $this->pubYear = $pubYear;
    }

    public function getConferenceStart(){
        return $this->conferenceStart;
    }

    public function setConferenceStart($conferenceStart){
        $this->conferenceStart = $conferenceStart;
    }

    public function getConferenceEnd(){
        return $this->conferenceEnd;
    }

    public function setConferenceEnd($conferenceEnd){
        $this->conferenceEnd = $conferenceEnd;
    }
    
    public function updateFromDto($dto) {
        if (isset($dto['eventId']) && filter_var($dto['eventId'], FILTER_VALIDATE_INT)) {
            $this->setEventId($dto['eventId']);
        }
        if (isset($dto['name'])) {
            $this->setName($dto['name']);
        }
        if (isset($dto['code'])) {
            $this->setCode($dto['code']);
        }
        if (isset($dto['conferenceStart'])) {
            $startDate = DateTime::createFromFormat("Y-m-d", $dto['conferenceStart']);
            if ($startDate) {
                $this->setConferenceStart($startDate);
            }
        }
        if (isset($dto['conferenceEnd'])) {
            $endDate = DateTime::createFromFormat("Y-m-d", $dto['conferenceEnd']);
            if ($endDate) {
                $this->setConferenceEnd($endDate);
            }
        }
        if (isset($dto['year'])) {
            $this->setYear($dto['year']);
        }
        if (isset($dto['series'])) {
            $this->setSeries($dto['series']);
        }
        if (isset($dto['seriesNumber'])) {
            $this->setSeriesNumber($dto['seriesNumber']);
        }
        if (isset($dto['issn'])) {
            $this->setIssn($dto['issn']);
        }
        if (isset($dto['isbn'])) {
            $this->setIsbn($dto['isbn']);
        }
        if (isset($dto['pubYear'])) {
            $this->setPubYear($dto['pubYear']);
        }
        if (isset($dto['pubMonth'])) {
            $this->setPubMonth($dto['pubMonth']);
        }
        if (isset($dto['doiCode'])) {
            $this->setDoiCode($dto['doiCode']);
        }
        if (isset($dto['useDoi'])) {
            $this->setUseDoi($dto['useDoi']);
        }
        if (isset($dto['baseUrl'])) {
            $this->setBaseUrl($dto['baseUrl']);
        }
        if (isset($dto['location'])) {
            $this->setLocation($dto['location']);
        }
        if (isset($dto['isPublished'])) {
            $this->setIsPublished($dto['isPublished']);
        }
        if (isset($dto['importUrl'])) {
            $this->setImportUrl($dto['importUrl']);
        }
    }

    function isFuture(): bool {
        return $this->getConferenceEnd() > new DateTime();
    }
}
