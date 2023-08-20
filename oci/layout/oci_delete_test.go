package layout

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/containers/image/v5/types"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	cp "github.com/otiai10/copy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReferenceDeleteImage(t *testing.T) {
	tmpDir := loadFixture(t, "delete_image")

	ref, err := NewReference(tmpDir, "latest")
	require.NoError(t, err)

	err = ref.DeleteImage(context.Background(), nil)
	require.NoError(t, err)

	// Check that all blobs were deleted
	blobsDir := filepath.Join(tmpDir, "blobs")
	files, err := os.ReadDir(filepath.Join(blobsDir, "sha256"))
	require.NoError(t, err)
	require.Empty(t, files)

	// Check that the index is empty as there is only one image in the fixture
	ociRef, ok := ref.(ociReference)
	require.True(t, ok)
	index, err := ociRef.getIndex()
	require.NoError(t, err)
	require.Equal(t, 0, len(index.Manifests))
}

func TestReferenceDeleteImage_sharedBlobDir(t *testing.T) {
	tmpDir := loadFixture(t, "delete_image_sharedblobsdir")

	ref, err := NewReference(tmpDir, "latest")
	require.NoError(t, err)

	sys := &types.SystemContext{OCISharedBlobDirPath: filepath.Join(tmpDir, "shared_blobs")}
	err = ref.DeleteImage(context.Background(), sys)
	require.NoError(t, err)

	// Check that the only blob in the local directory was deleted
	blobsDir := filepath.Join(tmpDir, "blobs")
	files, err := os.ReadDir(filepath.Join(blobsDir, "sha256"))
	require.NoError(t, err)
	require.Empty(t, files)

	// Check that the blobs in the shared blob directory are still present
	sharedBlobsDir := filepath.Join(tmpDir, "shared_blobs")
	files, err = os.ReadDir(filepath.Join(sharedBlobsDir, "sha256"))
	require.NoError(t, err)
	require.Equal(t, 2, len(files))

	// Check that the index is empty as there is only one image in the fixture
	ociRef, ok := ref.(ociReference)
	require.True(t, ok)
	index, err := ociRef.getIndex()
	require.NoError(t, err)
	require.Equal(t, 0, len(index.Manifests))
}

func TestReferenceDeleteImage_emptyImageName(t *testing.T) {
	tmpDir := loadFixture(t, "delete_image")

	ref, err := NewReference(tmpDir, "")
	require.NoError(t, err)

	err = ref.DeleteImage(context.Background(), nil)
	require.NoError(t, err)

	// Check that all blobs were deleted
	blobsDir := filepath.Join(tmpDir, "blobs")
	files, err := os.ReadDir(filepath.Join(blobsDir, "sha256"))
	require.NoError(t, err)
	require.Empty(t, files)

	// Check that the index is empty as there is only one image in the fixture
	ociRef, ok := ref.(ociReference)
	require.True(t, ok)
	index, err := ociRef.getIndex()
	require.NoError(t, err)
	require.Equal(t, 0, len(index.Manifests))
}

func TestReferenceDeleteImage_imageDoesNotExist(t *testing.T) {
	tmpDir := loadFixture(t, "delete_image")

	ref, err := NewReference(tmpDir, "does-not-exist")
	assert.NoError(t, err)

	err = ref.DeleteImage(context.Background(), nil)
	assert.Error(t, err)
}

func TestReferenceDeleteImage_moreThanOneImageInIndex(t *testing.T) {
	tmpDir := loadFixture(t, "delete_image_multipleimages")

	ref, err := NewReference(tmpDir, "3.2")
	require.NoError(t, err)

	err = ref.DeleteImage(context.Background(), nil)
	require.NoError(t, err)

	// Check that the relevant blobs were deleted/preservend
	blobsDir := filepath.Join(tmpDir, "blobs")
	blobDoesNotExist(t, blobsDir, "sha256:9a48d58d496b700f364686fbfbb2141ff5f0f25b033078a4c11fe597770b6fab") // menifest of the deleted image
	blobDoesNotExist(t, blobsDir, "sha256:8f891520c22dc085f86a1a9aef2e1165e63e7465ae2112df6bd1d7a115a12f8e") // config of the deleted image
	blobDoesNotExist(t, blobsDir, "sha256:d107df792639f1ee2fc4555597cb0eec8978b07e45a68f782965fd00a8964545") // layer of the deleted image
	blobExists(t, blobsDir, "sha256:f082a2f88d9405f9d583e5038c76290d10dbefdb9b2137301c1e867f6f43cff6")       // manifest of the other image present in the index
	blobExists(t, blobsDir, "sha256:a527179158cd5cebc11c152b8637b47ce96c838ba2aa0de66d14f45cedc11423")       // config of the other image present in the index
	blobExists(t, blobsDir, "sha256:bc584603ae5ca55d701f5134a0e5699056536885580ee929945bcbfeaf2633e6")       // layer of the other image present in the index

	// Check that the index doesn't contain the reference anymore
	ociRef, ok := ref.(ociReference)
	require.True(t, ok)
	descriptors, err := ociRef.getAllImageDescriptorsInDirectory()
	require.NoError(t, err)
	otherImageStillPresent := false //This will track that other images are still there
	for _, v := range descriptors {
		switch v.descriptor.Annotations[imgspecv1.AnnotationRefName] {
		case ociRef.image:
			assert.Fail(t, "image still present in the index after deletion")
		case "3.10.2":
			otherImageStillPresent = true
		}
	}
	require.True(t, otherImageStillPresent)
}

func TestReferenceDeleteImage_emptyImageNameButMoreThanOneImageInIndex(t *testing.T) {
	tmpDir := loadFixture(t, "delete_image_multipleimages")

	ref, err := NewReference(tmpDir, "")
	require.NoError(t, err)

	err = ref.DeleteImage(context.Background(), nil)
	require.Error(t, err)
}

func TestReferenceDeleteImage_someBlobsAreUsedByOtherImages(t *testing.T) {
	tmpDir := loadFixture(t, "delete_image_sharedblobs")

	ref, err := NewReference(tmpDir, "3.2")
	require.NoError(t, err)

	err = ref.DeleteImage(context.Background(), nil)
	require.NoError(t, err)

	// Check that the relevant blobs were deleted/preserved
	blobsDir := filepath.Join(tmpDir, "blobs")
	blobDoesNotExist(t, blobsDir, "sha256:2363edaccd5115dad0462eac535496a0b7b661311d1fb8ed7a1f51368bfa9f3a") // manifest for the image
	blobExists(t, blobsDir, "sha256:8f891520c22dc085f86a1a9aef2e1165e63e7465ae2112df6bd1d7a115a12f8e")       // configuration, used by another image too
	blobExists(t, blobsDir, "sha256:d107df792639f1ee2fc4555597cb0eec8978b07e45a68f782965fd00a8964545")       // layer, used by another image too
	blobDoesNotExist(t, blobsDir, "sha256:49b6418afb4ee08ba3956e4c344034c89a39ef1a451a55b44926ad9ee77e036b") // layer used by that image only

	// Check that the index doesn't contain the reference anymore
	ociRef, ok := ref.(ociReference)
	require.True(t, ok)
	descriptors, err := ociRef.getAllImageDescriptorsInDirectory()
	require.NoError(t, err)
	otherImagesStillPresent := make([]bool, 0, 2) //This will track that other images are still there
	for _, v := range descriptors {
		switch v.descriptor.Annotations[imgspecv1.AnnotationRefName] {
		case ociRef.image:
			assert.Fail(t, "image still present in the index after deletion")
		case "3.10.2":
			otherImagesStillPresent = append(otherImagesStillPresent, true)
		case "latest":
			otherImagesStillPresent = append(otherImagesStillPresent, true)
		}
	}
	assert.Equal(t, []bool{true, true}, otherImagesStillPresent)
}

func TestReferenceDeleteImage_inNestedIndex(t *testing.T) {
	tmpDir := loadFixture(t, "delete_image_nestedindex")

	ref, err := NewReference(tmpDir, "latest")
	require.NoError(t, err)

	err = ref.DeleteImage(context.Background(), nil)
	require.NoError(t, err)

	// Check that all relevant blobs were deleted/preserved
	blobsDir := filepath.Join(tmpDir, "blobs")
	blobDoesNotExist(t, blobsDir, "sha256:4a6da698b869046086d0e6ba846f8b931cb33bbaa5c68025b4fd55f67a4f0513") // manifest for the image
	blobDoesNotExist(t, blobsDir, "sha256:a527179158cd5cebc11c152b8637b47ce96c838ba2aa0de66d14f45cedc11423") // configuration for the image
	blobDoesNotExist(t, blobsDir, "sha256:0c8b263642b51b5c1dc40fe402ae2e97119c6007b6e52146419985ec1f0092dc") // layer used by that image only
	blobExists(t, blobsDir, "sha256:d107df792639f1ee2fc4555597cb0eec8978b07e45a68f782965fd00a8964545")       // layer used by another image in the index(es)

	// Check that a few new blobs have been created after index deletion/update
	blobDoesNotExist(t, blobsDir, "sha256:fbe294d1b627d6ee3c119d558dad8b1c4542cbc51c49ec45dd638921bc5921d0") // nested index 2 that contained the image and only that image
	blobDoesNotExist(t, blobsDir, "sha256:b2ff1c27b718b90910711aeda5e02ebbf4440659edd589cc458b3039ea91b35f") // nested index 1, should have been renamed - see next line
	blobExists(t, blobsDir, "sha256:13e9f5dde0af5d4303ef0e69d847bc14db6c86a7df616831e126821daf532982")       // new sha of the nested index

	// Check that the index has been update with the new nestedindex's sha
	ociRef, ok := ref.(ociReference)
	require.True(t, ok)
	index, err := ociRef.getIndex()
	require.NoError(t, err)
	assert.Equal(t, 1, len(index.Manifests))
}

func loadFixture(t *testing.T, fixtureName string) string {
	tmpDir := t.TempDir()
	err := cp.Copy(fmt.Sprintf("fixtures/%v/", fixtureName), tmpDir)
	require.NoError(t, err)
	return tmpDir
}
