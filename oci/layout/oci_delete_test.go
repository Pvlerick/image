package layout

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/containers/image/v5/types"
	digest "github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	cp "github.com/otiai10/copy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReferenceDeleteImage_onlyOneImage(t *testing.T) {
	tmpDir := loadFixture(t, "delete_image_only_one_image")

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

func TestReferenceDeleteImage_onlyOneImage_emptyImageName(t *testing.T) {
	tmpDir := loadFixture(t, "delete_image_only_one_image")

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

func TestReferenceDeleteImage_sharedBlobDir(t *testing.T) {
	tmpDir := loadFixture(t, "delete_image_shared_blobs_dir")

	ref, err := NewReference(tmpDir, "latest")
	require.NoError(t, err)

	sys := &types.SystemContext{OCISharedBlobDirPath: filepath.Join(tmpDir, "shared_blobs")}
	err = ref.DeleteImage(context.Background(), sys)
	require.NoError(t, err)

	// Check that the blobs in the shared blob directory are still present
	sharedBlobsDir := filepath.Join(tmpDir, "shared_blobs")
	files, err := os.ReadDir(filepath.Join(sharedBlobsDir, "sha256"))
	require.NoError(t, err)
	require.Equal(t, 3, len(files))

	// Check that the index is empty as there is only one image in the fixture
	ociRef, ok := ref.(ociReference)
	require.True(t, ok)
	index, err := ociRef.getIndex()
	require.NoError(t, err)
	require.Equal(t, 0, len(index.Manifests))
}

func TestReferenceDeleteImage_multipleImages(t *testing.T) {
	tmpDir := loadFixture(t, "delete_image_multiple_images")

	ref, err := NewReference(tmpDir, "3.17.5")
	require.NoError(t, err)

	err = ref.DeleteImage(context.Background(), nil)
	require.NoError(t, err)

	// Check that the relevant blobs were deleted/preservend
	blobsDir := filepath.Join(tmpDir, "blobs")
	files, err := os.ReadDir(filepath.Join(blobsDir, "sha256"))
	require.NoError(t, err)
	require.Equal(t, 16, len(files))
	assertBlobDoesNotExist(t, blobsDir, "sha256:5b2aba4d3c27bc6493633d0ec446b25c8d0a5c9cfe99894bcdff0aee80813805")
	assertBlobDoesNotExist(t, blobsDir, "sha256:df11bc189adeb50dadb3291a3a7f2c34b36e0efdba0df70f2c8a2d761b215cde")
	assertBlobDoesNotExist(t, blobsDir, "sha256:986315a0e599fac2b80eb31db2124dab8d3de04d7ca98b254999bd913c1f73fe")

	// Check the index
	ociRef, ok := ref.(ociReference)
	require.True(t, ok)
	// .. Check that the index has been reduced to the correct size
	index, err := ociRef.getIndex()
	require.NoError(t, err)
	require.Equal(t, 6, len(index.Manifests))
	// .. Check that the image is not in the index anymore
	for _, descriptor := range index.Manifests {
		switch descriptor.Annotations[imgspecv1.AnnotationRefName] {
		case "3.17.5":
			assert.Fail(t, "image still present in the index after deletion")
		default:
			continue
		}
	}
}

func TestReferenceDeleteImage_multipleImages_blobsUsedByOtherImages(t *testing.T) {
	tmpDir := loadFixture(t, "delete_image_multiple_images")

	ref, err := NewReference(tmpDir, "1.0.0")
	require.NoError(t, err)

	err = ref.DeleteImage(context.Background(), nil)
	require.NoError(t, err)

	// Check that the relevant blobs were deleted/preservend
	blobsDir := filepath.Join(tmpDir, "blobs")
	files, err := os.ReadDir(filepath.Join(blobsDir, "sha256"))
	require.NoError(t, err)
	require.Equal(t, 17, len(files))
	assertBlobExists(t, blobsDir, "sha256:df11bc189adeb50dadb3291a3a7f2c34b36e0efdba0df70f2c8a2d761b215cde")
	assertBlobDoesNotExist(t, blobsDir, "sha256:0dc27f36a618c110ae851662c13283e9fbc1b5a5de003befc4bcefa5a05d2eef")
	assertBlobDoesNotExist(t, blobsDir, "sha256:a6f737ac2b84bc463f2ff721af39588c69646c82f79f3808236178e02e35b922")

	// Check the index
	ociRef, ok := ref.(ociReference)
	require.True(t, ok)
	// .. Check that the index has been reduced to the correct size
	index, err := ociRef.getIndex()
	require.NoError(t, err)
	require.Equal(t, 6, len(index.Manifests))
	// .. Check that the image is not in the index anymore
	for _, descriptor := range index.Manifests {
		switch descriptor.Annotations[imgspecv1.AnnotationRefName] {
		case "1.0.0":
			assert.Fail(t, "image still present in the index after deletion")
		default:
			continue
		}
	}
}

func TestReferenceDeleteImage_multipleImages_imageDoesNotExist(t *testing.T) {
	tmpDir := loadFixture(t, "delete_image_multiple_images")

	ref, err := NewReference(tmpDir, "does-not-exist")
	assert.NoError(t, err)

	err = ref.DeleteImage(context.Background(), nil)
	assert.Error(t, err)
}

func TestReferenceDeleteImage_multipleImages_emptyImageName(t *testing.T) {
	tmpDir := loadFixture(t, "delete_image_multiple_images")

	ref, err := NewReference(tmpDir, "")
	require.NoError(t, err)

	err = ref.DeleteImage(context.Background(), nil)
	require.Error(t, err)
}

func TestReferenceDeleteImage_multipleImages_nestedIndexImage(t *testing.T) {
	tmpDir := loadFixture(t, "delete_image_multiple_images")

	ref, err := NewReference(tmpDir, "3.16.7")
	require.NoError(t, err)

	err = ref.DeleteImage(context.Background(), nil)
	require.NoError(t, err)

	// Check that the relevant blobs were deleted/preservend
	blobsDir := filepath.Join(tmpDir, "blobs")
	files, err := os.ReadDir(filepath.Join(blobsDir, "sha256"))
	require.NoError(t, err)
	require.Equal(t, 12, len(files))
	assertBlobDoesNotExist(t, blobsDir, "sha256:861d3c014b0e3edcf80e6221247d6b2921a4f892feb9bafe9515b9975b78c44f")
	assertBlobDoesNotExist(t, blobsDir, "sha256:39c524417bb4228f9fcb0aef43a680b5fd6b9f3a1df2fd50509d047e47dad8be")
	assertBlobDoesNotExist(t, blobsDir, "sha256:f732172ad8d2a666550fa3ec37a5153d59acc95744562ae64cf62ded46de101a")
	assertBlobDoesNotExist(t, blobsDir, "sha256:02ea786cb1ff44d997661886a4186cbd8a1dc466938712bf7281379209476022")
	assertBlobDoesNotExist(t, blobsDir, "sha256:be6036f9b6a4e120a04868c47f1b8674f58b2fe5e410cba9f585a13ca8946cf0")
	assertBlobDoesNotExist(t, blobsDir, "sha256:7ffdfe7d276286b39a203dcc247949cf47c91d2d5e10a53a675c0962ed9e4402")
	assertBlobDoesNotExist(t, blobsDir, "sha256:e2f7e0374fd6a03d9c373f4d9a0c7802045cc3ddcc1433e89d83b81fa7007242")

	// Check the index
	ociRef, ok := ref.(ociReference)
	require.True(t, ok)
	// .. Check that the index has been reduced to the correct size
	index, err := ociRef.getIndex()
	require.NoError(t, err)
	require.Equal(t, 6, len(index.Manifests))
	// .. Check that the image is not in the index anymore
	for _, descriptor := range index.Manifests {
		switch descriptor.Annotations[imgspecv1.AnnotationRefName] {
		case "3.16.7":
			assert.Fail(t, "image still present in the index after deletion")
		default:
			continue
		}
	}
}

func TestReferenceDeleteImage_multipleImages_nestedIndexImage_refWithSameContent(t *testing.T) {
	tmpDir := loadFixture(t, "delete_image_multiple_images")

	ref, err := NewReference(tmpDir, "3.18.3")
	require.NoError(t, err)

	err = ref.DeleteImage(context.Background(), nil)
	require.NoError(t, err)

	// Check that the relevant blobs were deleted/preservend
	blobsDir := filepath.Join(tmpDir, "blobs")
	files, err := os.ReadDir(filepath.Join(blobsDir, "sha256"))
	require.NoError(t, err)
	require.Equal(t, 19, len(files))

	// Check the index
	ociRef, ok := ref.(ociReference)
	require.True(t, ok)
	// .. Check that the index has been reduced to the correct size
	index, err := ociRef.getIndex()
	require.NoError(t, err)
	require.Equal(t, 6, len(index.Manifests))
}

func loadFixture(t *testing.T, fixtureName string) string {
	tmpDir := t.TempDir()
	err := cp.Copy(fmt.Sprintf("fixtures/%v/", fixtureName), tmpDir)
	require.NoError(t, err)
	return tmpDir
}

func assertBlobExists(t *testing.T, blobsDir string, blobDigest string) {
	digest, err := digest.Parse(blobDigest)
	require.NoError(t, err)
	blobPath := filepath.Join(blobsDir, digest.Algorithm().String(), digest.Hex())
	_, err = os.Stat(blobPath)
	require.NoError(t, err)
}

func assertBlobDoesNotExist(t *testing.T, blobsDir string, blobDigest string) {
	digest, err := digest.Parse(blobDigest)
	require.NoError(t, err)
	blobPath := filepath.Join(blobsDir, digest.Algorithm().String(), digest.Hex())
	_, err = os.Stat(blobPath)
	require.True(t, os.IsNotExist(err))
}
