package layout

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/containers/image/v5/internal/testing/explicitfilepath-tmpdir"
	"github.com/containers/image/v5/types"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetManifestDescriptor(t *testing.T) {
	emptyDir := t.TempDir()

	for _, c := range []struct {
		dir, image string
		expected   *imgspecv1.Descriptor // nil if a failure ie expected. errorIs / errorAs allows more specific checks.
		errorIs    error
		errorAs    any
	}{
		{ // Index is missing
			dir:      emptyDir,
			image:    "",
			expected: nil,
		},
		{ // A valid reference to the only manifest
			dir:   "fixtures/manifest",
			image: "",
			expected: &imgspecv1.Descriptor{
				MediaType:   "application/vnd.oci.image.manifest.v1+json",
				Digest:      "sha256:84afb6189c4d69f2d040c5f1dc4e0a16fed9b539ce9cfb4ac2526ae4e0576cc0",
				Size:        496,
				Annotations: map[string]string{"org.opencontainers.image.ref.name": "v0.1.1"},
				Platform: &imgspecv1.Platform{
					Architecture: "amd64",
					OS:           "linux",
				},
			},
		},
		{ // An ambiguous reference to a multi-manifest directory
			dir:      "fixtures/two_images_manifest",
			image:    "",
			expected: nil,
			errorIs:  ErrMoreThanOneImage,
		},
		{ // A valid reference in a multi-manifest directory
			dir:   "fixtures/name_lookups",
			image: "a",
			expected: &imgspecv1.Descriptor{
				MediaType:   "application/vnd.oci.image.manifest.v1+json",
				Digest:      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				Size:        1,
				Annotations: map[string]string{"org.opencontainers.image.ref.name": "a"},
			},
		},
		{ // A valid reference in a multi-manifest directory
			dir:   "fixtures/name_lookups",
			image: "b",
			expected: &imgspecv1.Descriptor{
				MediaType:   "application/vnd.oci.image.manifest.v1+json",
				Digest:      "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				Size:        2,
				Annotations: map[string]string{"org.opencontainers.image.ref.name": "b"},
			},
		},
		{ // No entry found
			dir:      "fixtures/name_lookups",
			image:    "this-does-not-exist",
			expected: nil,
			errorAs:  &ImageNotFoundError{},
		},
		{ // Entries with invalid MIME types found
			dir:      "fixtures/name_lookups",
			image:    "invalid-mime",
			expected: nil,
		},
	} {
		ref, err := NewReference(c.dir, c.image)
		require.NoError(t, err)

		res, err := ref.(ociReference).getManifestDescriptor()
		if c.expected != nil {
			require.NoError(t, err)
			assert.Equal(t, *c.expected, res)
		} else {
			require.Error(t, err)
			if c.errorIs != nil {
				assert.ErrorIs(t, err, c.errorIs)
			}
			if c.errorAs != nil {
				assert.ErrorAs(t, err, &c.errorAs)
			}
		}
	}
}

func TestTransportName(t *testing.T) {
	assert.Equal(t, "oci", Transport.Name())
}

func TestTransportParseReference(t *testing.T) {
	testParseReference(t, Transport.ParseReference)
}

func TestTransportValidatePolicyConfigurationScope(t *testing.T) {
	for _, scope := range []string{
		"/etc",
		"/this/does/not/exist",
	} {
		err := Transport.ValidatePolicyConfigurationScope(scope)
		assert.NoError(t, err, scope)
	}

	for _, scope := range []string{
		"relative/path",
		"/",
		"/double//slashes",
		"/has/./dot",
		"/has/dot/../dot",
		"/trailing/slash/",
	} {
		err := Transport.ValidatePolicyConfigurationScope(scope)
		assert.Error(t, err, scope)
	}
}

func TestParseReference(t *testing.T) {
	testParseReference(t, ParseReference)
}

// testParseReference is a test shared for Transport.ParseReference and ParseReference.
func testParseReference(t *testing.T, fn func(string) (types.ImageReference, error)) {
	tmpDir := t.TempDir()

	for _, path := range []string{
		"/",
		"/etc",
		tmpDir,
		"relativepath",
		tmpDir + "/thisdoesnotexist",
	} {
		for _, image := range []struct{ suffix, image string }{
			{":notlatest:image", "notlatest:image"},
			{":latestimage", "latestimage"},
			{":", ""},
			{"", ""},
		} {
			input := path + image.suffix
			ref, err := fn(input)
			require.NoError(t, err, input)
			ociRef, ok := ref.(ociReference)
			require.True(t, ok)
			assert.Equal(t, path, ociRef.dir, input)
			assert.Equal(t, image.image, ociRef.image, input)
		}
	}

	_, err := fn(tmpDir + ":invalid'image!value@")
	assert.Error(t, err)
}

func TestNewReference(t *testing.T) {
	const (
		imageValue   = "imageValue"
		noImageValue = ""
	)

	tmpDir := t.TempDir()

	ref, err := NewReference(tmpDir, imageValue)
	require.NoError(t, err)
	ociRef, ok := ref.(ociReference)
	require.True(t, ok)
	assert.Equal(t, tmpDir, ociRef.dir)
	assert.Equal(t, imageValue, ociRef.image)

	ref, err = NewReference(tmpDir, noImageValue)
	require.NoError(t, err)
	ociRef, ok = ref.(ociReference)
	require.True(t, ok)
	assert.Equal(t, tmpDir, ociRef.dir)
	assert.Equal(t, noImageValue, ociRef.image)

	_, err = NewReference(tmpDir+"/thisparentdoesnotexist/something", imageValue)
	assert.Error(t, err)

	_, err = NewReference(tmpDir, "invalid'image!value@")
	assert.Error(t, err)

	_, err = NewReference(tmpDir+"/has:colon", imageValue)
	assert.Error(t, err)
}

// refToTempOCI creates a temporary directory and returns an reference to it.
func refToTempOCI(t *testing.T) (types.ImageReference, string) {
	tmpDir := t.TempDir()
	m := `{
		"schemaVersion": 2,
		"manifests": [
		{
			"mediaType": "application/vnd.oci.image.manifest.v1+json",
			"size": 7143,
			"digest": "sha256:e692418e4cbaf90ca69d05a66403747baa33ee08806650b51fab815ad7fc331f",
			"platform": {
				"architecture": "ppc64le",
				"os": "linux"
			},
			"annotations": {
				"org.opencontainers.image.ref.name": "imageValue"
			}
		}
		]
	}
`
	err := os.WriteFile(filepath.Join(tmpDir, "index.json"), []byte(m), 0644)
	require.NoError(t, err)
	ref, err := NewReference(tmpDir, "imageValue")
	require.NoError(t, err)
	return ref, tmpDir
}

func TestReferenceTransport(t *testing.T) {
	ref, _ := refToTempOCI(t)
	assert.Equal(t, Transport, ref.Transport())
}

func TestReferenceStringWithinTransport(t *testing.T) {
	tmpDir := t.TempDir()

	for _, c := range []struct{ input, result string }{
		{"/dir1:notlatest:notlatest", "/dir1:notlatest:notlatest"}, // Explicit image
		{"/dir3:", "/dir3:"}, // No image
	} {
		ref, err := ParseReference(tmpDir + c.input)
		require.NoError(t, err, c.input)
		stringRef := ref.StringWithinTransport()
		assert.Equal(t, tmpDir+c.result, stringRef, c.input)
		// Do one more round to verify that the output can be parsed, to an equal value.
		ref2, err := Transport.ParseReference(stringRef)
		require.NoError(t, err, c.input)
		stringRef2 := ref2.StringWithinTransport()
		assert.Equal(t, stringRef, stringRef2, c.input)
	}
}

func TestReferenceDockerReference(t *testing.T) {
	ref, _ := refToTempOCI(t)
	assert.Nil(t, ref.DockerReference())
}

func TestReferencePolicyConfigurationIdentity(t *testing.T) {
	ref, tmpDir := refToTempOCI(t)

	assert.Equal(t, tmpDir, ref.PolicyConfigurationIdentity())
	// A non-canonical path.  Test just one, the various other cases are
	// tested in explicitfilepath.ResolvePathToFullyExplicit.
	ref, err := NewReference(tmpDir+"/.", "image2")
	require.NoError(t, err)
	assert.Equal(t, tmpDir, ref.PolicyConfigurationIdentity())

	// "/" as a corner case.
	ref, err = NewReference("/", "image3")
	require.NoError(t, err)
	assert.Equal(t, "/", ref.PolicyConfigurationIdentity())
}

func TestReferencePolicyConfigurationNamespaces(t *testing.T) {
	ref, tmpDir := refToTempOCI(t)
	// We don't really know enough to make a full equality test here.
	ns := ref.PolicyConfigurationNamespaces()
	require.NotNil(t, ns)
	assert.True(t, len(ns) >= 2)
	assert.Equal(t, tmpDir, ns[0])
	assert.Equal(t, filepath.Dir(tmpDir), ns[1])

	// Test with a known path which should exist. Test just one non-canonical
	// path, the various other cases are tested in explicitfilepath.ResolvePathToFullyExplicit.
	//
	// It would be nice to test a deeper hierarchy, but it is not obvious what
	// deeper path is always available in the various distros, AND is not likely
	// to contains a symbolic link.
	for _, path := range []string{"/usr/share", "/usr/share/./."} {
		_, err := os.Lstat(path)
		require.NoError(t, err)
		ref, err := NewReference(path, "someimage")
		require.NoError(t, err)
		ns := ref.PolicyConfigurationNamespaces()
		require.NotNil(t, ns)
		assert.Equal(t, []string{"/usr/share", "/usr"}, ns)
	}

	// "/" as a corner case.
	ref, err := NewReference("/", "image3")
	require.NoError(t, err)
	assert.Equal(t, []string{}, ref.PolicyConfigurationNamespaces())
}

func TestReferenceNewImage(t *testing.T) {
	ref, _ := refToTempOCI(t)
	_, err := ref.NewImage(context.Background(), nil)
	assert.Error(t, err)
}

func TestReferenceNewImageSource(t *testing.T) {
	ref, _ := refToTempOCI(t)
	src, err := ref.NewImageSource(context.Background(), nil)
	assert.NoError(t, err)
	defer src.Close()
}

func TestReferenceNewImageDestination(t *testing.T) {
	ref, _ := refToTempOCI(t)
	dest, err := ref.NewImageDestination(context.Background(), nil)
	assert.NoError(t, err)
	defer dest.Close()
}

type fakeImageSpec struct {
	name     string
	manifest string
	config   string
	layers   []string
}

func generateOciIndexAndContent(t *testing.T, images ...fakeImageSpec) string {
	tmpDir := t.TempDir()

	// Create blobs dir - assumption: all the content is sha256 digest-ed
	blobsDir := filepath.Join(tmpDir, "blobs", string(digest.SHA256))
	err := os.MkdirAll(blobsDir, 0777)
	require.NoError(t, err)

	saveJson := func(path string, content any) {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0644)
		require.NoError(t, err)
		defer file.Close()

		err = json.NewEncoder(file).Encode(content)
		require.NoError(t, err)
	}

	indexManifests := make([]imgspecv1.Descriptor, 0, len(images))

	for _, image := range images {
		// Create the layers blobs
		layers := make([]imgspecv1.Descriptor, 0, len(image.layers))

		for _, layer := range image.layers {
			layerDigest, err := digest.Parse(layer)
			require.NoError(t, err)
			path := filepath.Join(blobsDir, layerDigest.Hex())
			content := []byte("ABCDEF")
			err = os.WriteFile(path, content, 0644)
			require.NoError(t, err)
			layers = append(layers, imgspecv1.Descriptor{
				MediaType: imgspecv1.MediaTypeImageLayerGzip,
				Digest:    layerDigest,
			})
		}

		// Create the config blob
		configDigest, err := digest.Parse(image.config)
		require.NoError(t, err)

		config := imgspecv1.Descriptor{}
		saveJson(filepath.Join(blobsDir, configDigest.Hex()), config)

		// Create the manifest blob
		manifestDigest, err := digest.Parse(image.manifest)
		require.NoError(t, err)

		manifest := imgspecv1.Manifest{
			Versioned: specs.Versioned{SchemaVersion: 2},
			MediaType: imgspecv1.MediaTypeImageManifest,
			Config: imgspecv1.Descriptor{
				MediaType: imgspecv1.MediaTypeImageConfig,
				Digest:    configDigest,
				Size:      10,
			},
			Layers: layers,
		}

		saveJson(filepath.Join(blobsDir, manifestDigest.Hex()), manifest)

		// Populate the index
		indexManifests = append(indexManifests, imgspecv1.Descriptor{
			MediaType: imgspecv1.MediaTypeImageManifest,
			Digest:    manifestDigest,
			Annotations: map[string]string{
				imgspecv1.AnnotationRefName: image.name,
			},
		})
	}

	// Create the index
	index := imgspecv1.Index{
		Versioned: specs.Versioned{SchemaVersion: 2},
		Manifests: indexManifests,
	}

	saveJson(filepath.Join(tmpDir, "index.json"), index)

	return tmpDir
}

func TestReferenceDeleteImage(t *testing.T) {
	image := fakeImageSpec{
		name:     "image-1:latest",
		manifest: "sha256:7df521835a17f9308c7d89484c6f6c630f6d5ed7126df8485f0e6ec0ec1cc9bc",
		config:   "sha256:d0cc41b6cef5cc972a521ce9b81995c39533f2430df03cb62f44799b15d21217",
		layers: []string{
			"sha256:ebfb402c523af279c1b58751b9c3c48d250906f4e57ef8af4fc0540e290281dc",
			"sha256:f37ee95567a8ca93744f71634155b45ac405f509fa1e5d1a497b36a54619be56",
		},
	}

	tmpDir := generateOciIndexAndContent(t, []fakeImageSpec{image}...)

	ref, err := NewReference(tmpDir, image.name)
	require.NoError(t, err)

	err = ref.DeleteImage(context.Background(), nil)
	require.NoError(t, err)

	// Check that all blobs were deleted
	blobsDir := filepath.Join(tmpDir, "blobs")
	blobDoesNotExist(t, blobsDir, image.manifest)
	blobDoesNotExist(t, blobsDir, image.config)
	for _, layer := range image.layers {
		blobDoesNotExist(t, blobsDir, layer)
	}

	// Check that the index doesn't contain the reference anymore
	ociRef, ok := ref.(ociReference)
	require.True(t, ok)
	index, err := ociRef.getIndex()
	require.NoError(t, err)
	for _, v := range index.Manifests {
		if v.Annotations[imgspecv1.AnnotationRefName] == ociRef.image {
			assert.Fail(t, "image still present in the index after deletion")
		}
	}
}

func TestReferenceDeleteImage_emptyImageName(t *testing.T) {
	image := fakeImageSpec{
		name:     "image-1:latest",
		manifest: "sha256:7df521835a17f9308c7d89484c6f6c630f6d5ed7126df8485f0e6ec0ec1cc9bc",
		config:   "sha256:d0cc41b6cef5cc972a521ce9b81995c39533f2430df03cb62f44799b15d21217",
		layers: []string{
			"sha256:ebfb402c523af279c1b58751b9c3c48d250906f4e57ef8af4fc0540e290281dc",
		},
	}

	tmpDir := generateOciIndexAndContent(t, []fakeImageSpec{image}...)

	ref, err := NewReference(tmpDir, "")
	require.NoError(t, err)

	err = ref.DeleteImage(context.Background(), nil)
	require.NoError(t, err)

	// Check that all blobs were deleted
	blobsDir := filepath.Join(tmpDir, "blobs")
	blobDoesNotExist(t, blobsDir, image.manifest)
	blobDoesNotExist(t, blobsDir, image.config)
	for _, layer := range image.layers {
		blobDoesNotExist(t, blobsDir, layer)
	}

	// Check that the index doesn't contain the reference anymore
	ociRef, ok := ref.(ociReference)
	require.True(t, ok)
	index, err := ociRef.getIndex()
	require.NoError(t, err)
	for _, v := range index.Manifests {
		if v.Annotations[imgspecv1.AnnotationRefName] == image.name {
			assert.Fail(t, "image still present in the index after deletion")
		}
	}
}

func TestReferenceDeleteImage_emptyImageNameButMoreThanOneImageInIndex(t *testing.T) {
	images := []fakeImageSpec{
		{
			name:     "image-1:latest",
			manifest: "sha256:7df521835a17f9308c7d89484c6f6c630f6d5ed7126df8485f0e6ec0ec1cc9bc",
			config:   "sha256:d0cc41b6cef5cc972a521ce9b81995c39533f2430df03cb62f44799b15d21217",
			layers: []string{
				"sha256:ebfb402c523af279c1b58751b9c3c48d250906f4e57ef8af4fc0540e290281dc",
			},
		},
		{
			name:     "image-2:latest",
			manifest: "sha256:b4679e9e04b749cab43f1534ae5c82a521b745c6346b90a7034ca72d3ed38beb",
			config:   "sha256:eb6bea08ad372676ed419b424557f517e9b5190b0af38614cb30548908fcf794",
			layers: []string{
				"sha256:623802888f95381343c8511943d774b6ac96ff8710fc40b7b47845a50d038c2c",
			},
		},
	}

	tmpDir := generateOciIndexAndContent(t, images...)

	ref, err := NewReference(tmpDir, "")
	require.NoError(t, err)

	err = ref.DeleteImage(context.Background(), nil)
	require.Error(t, err)
}

func TestReferenceDeleteImage_imageDoesNotExist(t *testing.T) {
	image := fakeImageSpec{
		name:     "image-1:latest",
		manifest: "sha256:7df521835a17f9308c7d89484c6f6c630f6d5ed7126df8485f0e6ec0ec1cc9bc",
		config:   "sha256:d0cc41b6cef5cc972a521ce9b81995c39533f2430df03cb62f44799b15d21217",
		layers: []string{
			"sha256:ebfb402c523af279c1b58751b9c3c48d250906f4e57ef8af4fc0540e290281dc",
			"sha256:f37ee95567a8ca93744f71634155b45ac405f509fa1e5d1a497b36a54619be56",
		},
	}

	tmpDir := generateOciIndexAndContent(t, []fakeImageSpec{image}...)

	ref, err := NewReference(tmpDir, "does-not:exist")
	assert.NoError(t, err)

	err = ref.DeleteImage(context.Background(), nil)
	assert.Error(t, err)
}

func TestReferenceDeleteImage_someLayersAreReferencedByOtherImages(t *testing.T) {
	const commonLayer = "sha256:bff18d814a6d85fb3ea9b1ee7271b831e204ff0bd88a17c4bfcf9a83ed07e8f8"
	images := []fakeImageSpec{
		{
			name:     "image-1:latest",
			manifest: "sha256:7df521835a17f9308c7d89484c6f6c630f6d5ed7126df8485f0e6ec0ec1cc9bc",
			config:   "sha256:d0cc41b6cef5cc972a521ce9b81995c39533f2430df03cb62f44799b15d21217",
			layers: []string{
				"sha256:ebfb402c523af279c1b58751b9c3c48d250906f4e57ef8af4fc0540e290281dc",
				commonLayer,
				"sha256:f37ee95567a8ca93744f71634155b45ac405f509fa1e5d1a497b36a54619be56",
			},
		},
		{
			name:     "image-2:latest",
			manifest: "sha256:b4679e9e04b749cab43f1534ae5c82a521b745c6346b90a7034ca72d3ed38beb",
			config:   "sha256:eb6bea08ad372676ed419b424557f517e9b5190b0af38614cb30548908fcf794",
			layers: []string{
				"sha256:623802888f95381343c8511943d774b6ac96ff8710fc40b7b47845a50d038c2c",
				commonLayer,
				"sha256:66a79b735a97ede9e52267492df7c4a7ee6e287113efe3e7def0c6f73f158589",
			},
		},
	}

	tmpDir := generateOciIndexAndContent(t, images...)

	image := images[0]
	ref, err := NewReference(tmpDir, image.name)
	require.NoError(t, err)

	err = ref.DeleteImage(context.Background(), nil)
	require.NoError(t, err)

	// Check that all relevant blobs were deleted
	blobsDir := filepath.Join(tmpDir, "blobs")
	blobDoesNotExist(t, blobsDir, image.manifest)
	blobDoesNotExist(t, blobsDir, image.config)
	blobDoesNotExist(t, blobsDir, image.layers[0])
	blobDoesNotExist(t, blobsDir, image.layers[2])

	// Check that the blob used by another image was not deleted
	commonBlobDigest, err := digest.Parse(commonLayer)
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(blobsDir, commonBlobDigest.Algorithm().String(), commonBlobDigest.Hex()))
	require.NoError(t, err)

	// Check that the index doesn't contain the reference anymore
	ociRef, ok := ref.(ociReference)
	require.True(t, ok)
	index, err := ociRef.getIndex()
	require.NoError(t, err)
	for _, v := range index.Manifests {
		if v.Annotations[imgspecv1.AnnotationRefName] == image.name {
			assert.Fail(t, "image still present in the index after deletion")
		}
	}
}

func TestReferenceOCILayoutPath(t *testing.T) {
	ref, tmpDir := refToTempOCI(t)
	ociRef, ok := ref.(ociReference)
	require.True(t, ok)
	assert.Equal(t, tmpDir+"/oci-layout", ociRef.ociLayoutPath())
}

func TestReferenceIndexPath(t *testing.T) {
	ref, tmpDir := refToTempOCI(t)
	ociRef, ok := ref.(ociReference)
	require.True(t, ok)
	assert.Equal(t, tmpDir+"/index.json", ociRef.indexPath())
}

func TestReferenceBlobPath(t *testing.T) {
	const hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	ref, tmpDir := refToTempOCI(t)
	ociRef, ok := ref.(ociReference)
	require.True(t, ok)
	bp, err := ociRef.blobPath("sha256:"+hex, "")
	assert.NoError(t, err)
	assert.Equal(t, tmpDir+"/blobs/sha256/"+hex, bp)
}

func TestReferenceSharedBlobPathShared(t *testing.T) {
	const hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	ref, _ := refToTempOCI(t)
	ociRef, ok := ref.(ociReference)
	require.True(t, ok)
	bp, err := ociRef.blobPath("sha256:"+hex, "/external/path")
	assert.NoError(t, err)
	assert.Equal(t, "/external/path/sha256/"+hex, bp)
}

func TestReferenceBlobPathInvalid(t *testing.T) {
	const hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	ref, _ := refToTempOCI(t)
	ociRef, ok := ref.(ociReference)
	require.True(t, ok)
	_, err := ociRef.blobPath(hex, "")
	assert.ErrorContains(t, err, "unexpected digest reference "+hex)
}

func blobDoesNotExist(t *testing.T, blobsDir string, blobDigest string) {
	digest, err := digest.Parse(blobDigest)
	require.NoError(t, err)
	blobPath := filepath.Join(blobsDir, digest.Algorithm().String(), digest.Hex())
	_, err = os.Stat(blobPath)
	require.True(t, os.IsNotExist(err))
}
