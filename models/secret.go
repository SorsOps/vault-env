package models

import (
	"errors"
	"fmt"
)

type SecretType string

const (
	EnvironmentSecret SecretType = "ENV"
	File              SecretType = "FILE"
)

type OSFormat string

const (
	WINDOWS OSFormat = "WINDOWS"
	NIX     OSFormat = "FILE"
)

type SecretsRoot struct {
	Secrets Secrets `yaml:"secrets,omitempty"`
}

type Secrets struct {
	Version    *string      `yaml:"version"`
	Collection []Collection `yaml:"collections,omitempty"`
	/**
	 * Output is the default output file for all secrets
	 * If a secret has a file specified, it will override this value
	 */
	Output *string `yaml:"output,omitempty"`
}

type Collection struct {
	Name   *string  `yaml:"name"`
	Values []Secret `yaml:"values"`
}

type Alias struct {
	Field *string `yaml:"field"`
	Name  *string `yaml:"name"`
}

type Secret struct {
	Engine *string `yaml:"engine,omitempty"`
	Root   *string `yaml:"root,omitempty"`
	Path   *string `yaml:"path,omitempty"`
	Field  *string `yaml:"field,omitempty"`
	// ENV or FILE
	Type SecretType `yaml:"type,omitempty"`
	File *string    `yaml:"file,omitempty"`
	//Only usable by kv-v2
	Version *int `yaml:"version,omitempty"`
	/**
	 * Aliases are used to map a secret to a different name
	 * IE if you have a secret named `password` but want to use it as `PASSWORD`
	 */
	Aliases   []Alias `yaml:"aliases,omitempty"`
	Namespace *string `yaml:"namespace,omitempty"`
}

func initCollection(p *Secrets, collections []Collection) ([]Collection, error) {

	defaultedCollections := make([]Collection, len(collections))

	for i, value := range collections {

		newCollection, err := value.InitDefaults(p)
		if err != nil {
			return nil, err
		}
		defaultedCollections[i] = *newCollection
	}

	return defaultedCollections, nil
}

func (p *Secrets) InitDefaults() (*Secrets, error) {

	var output *string
	if p.Output != nil {
		output = p.Output
	}

	if p.Version == nil {
		return nil, errors.New("`version` must be passed")
	}

	if *p.Version != "1.0.0" {
		return nil, errors.New("Only major version `1` is supported")
	}

	newCollections, err := initCollection(p, p.Collection)

	if err != nil {
		return nil, err
	}

	var newSecrets = &Secrets{
		Output:     output,
		Collection: newCollections,
	}
	return newSecrets, nil
}

func (p *Collection) InitDefaults(secrets *Secrets) (*Collection, error) {

	if p.Name == nil || len(*p.Name) == 0 {
		return nil, errors.New("`name` must be provided. None detected")
	}

	defaultedSecrets := make([]Secret, len(p.Values))

	for i, value := range p.Values {

		newSecret, err := value.InitDefaults(secrets)
		if err != nil {
			return nil, err
		}
		defaultedSecrets[i] = *newSecret
	}

	return &Collection{
		Name:   p.Name,
		Values: defaultedSecrets,
	}, nil
}

func (p *Alias) InitDefaults() (*Alias, error) {

	if p.Field == nil || len(*p.Field) == 0 {
		return nil, errors.New("`field` must be provided. None detected")
	}
	if p.Name == nil {
		return nil, errors.New("`name` must be provided. None detected")
	}
	return p, nil
}

func (p *Secret) InitDefaults(secrets *Secrets) (*Secret, error) {

	var secretType SecretType
	if len(p.Type) == 0 {
		secretType = File
	} else {
		secretType = p.Type
	}

	if p.Field != nil && len(p.Aliases) > 1 {
		return nil, errors.New("For a single field value, you may only have one alias")
	}

	var fileOutput *string = p.File
	if secretType == File && p.File == nil {
		fileOutput = secrets.Output
	}

	fieldLookup := make(map[string]int)
	lookup := make(map[string]int)
	for _, v := range p.Aliases {
		_, err := v.InitDefaults()
		if err != nil {
			return nil, err
		}
		lookup[*v.Name]++
		fieldLookup[*v.Field]++

		if lookup[*v.Name] > 1 {
			return nil, fmt.Errorf("Non unique alias name `%s` detected", *v.Name)
		}
		if fieldLookup[*v.Field] > 1 {
			return nil, fmt.Errorf("Non unique alias field `%s` detected", *v.Field)
		}
	}

	var newSecret = &Secret{
		Engine:    p.Engine,
		Path:      p.Path,
		Field:     p.Field,
		Root:      p.Root,
		Type:      secretType,
		Version:   p.Version,
		Aliases:   p.Aliases,
		File:      fileOutput,
		Namespace: p.Namespace,
	}

	return newSecret, nil
}
