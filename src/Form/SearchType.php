<?php

namespace App\Form;

use App\Entity\Author;
use App\Entity\Search;
use App\Form\Type\TagsAsInputType;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

class SearchType extends AbstractType
{
    /**
     * {@inheritdoc}
     */
    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $builder
            ->add('conference', null, ['label'=>"Conference Code / Name", "attr"=>["class"=>"conference-typeahead","autocomplete"=>"off"]])
            ->add('date', null,["label"=>"Conference Date", "attr"=>["class"=>"conference-date-typeahead","autocomplete"=>"off"]])
            ->add('location', null, ["label"=>"Conference Location", "attr"=>["class"=>"conference-location-typeahead","autocomplete"=>"off"]])
            ->add('paperId', null, array("label"=>"Paper ID"))
            ->add('author', TextType::class, ["required"=>false,
                "label"=> "Author/s (e.g. A. Person)"])
            ->add('title', null, ["label"=>"Paper Title"])

            ;
    }/**
     * {@inheritdoc}
     */
    public function configureOptions(OptionsResolver $resolver)
    {
        $resolver->setDefaults(array(
            'data_class' => Search::class,
            "csrf_protection" => false
        ));
    }

    /**
     * {@inheritdoc}
     */
    public function getBlockPrefix()
    {
        return 'appbundle_search';
    }


}
