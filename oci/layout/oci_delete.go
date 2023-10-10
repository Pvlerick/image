package layout

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"

	"github.com/containers/image/v5/internal/set"
	"github.com/containers/image/v5/types"
	digest "github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
)

// DeleteImage deletes the named image from the directory, if supported.
func (ref ociReference) DeleteImage(ctx context.Context, sys *types.SystemContext) error {
	if sys != nil && sys.OCISharedBlobDirPath != "" {
		// In case of shared blob dir usage, only update the index
		return ref.deleteReferenceFromIndex()
	}

	descriptor, err := ref.getManifestDescriptor()
	if err != nil {
		return err
	}

	var blobsUsedByImage map[digest.Digest]int

	switch descriptor.MediaType {
	case imgspecv1.MediaTypeImageManifest:
		blobsUsedByImage, err = ref.getBlobsUsedInSingleImage(&descriptor)
	case imgspecv1.MediaTypeImageIndex:
		blobsUsedByImage, err = ref.getBlobsUsedInImageIndex(&descriptor)
	default:
		return fmt.Errorf("unsupported mediaType in index: %q", descriptor.MediaType)
	}
	if err != nil {
		return err
	}

	blobsToDelete, err := ref.getBlobsToDelete(blobsUsedByImage)
	if err != nil {
		return err
	}

	err = ref.deleteBlobs(blobsToDelete)
	if err != nil {
		return err
	}

	return ref.deleteReferenceFromIndex()
}

func (ref ociReference) getBlobsUsedInSingleImage(descriptor *imgspecv1.Descriptor) (map[digest.Digest]int, error) {
	manifest, err := ref.getManifest(descriptor)
	if err != nil {
		return nil, err
	}
	blobsUsedInManifest := ref.getBlobsUsedInManifest(manifest)
	blobsUsedInManifest[descriptor.Digest]++ // Add the current manifest to the list of blobs used by this reference

	return blobsUsedInManifest, nil
}

func (ref ociReference) getBlobsUsedInImageIndex(descriptor *imgspecv1.Descriptor) (map[digest.Digest]int, error) {
	blobPath, err := ref.blobPath(descriptor.Digest, "")
	if err != nil {
		return nil, err
	}
	index, err := parseIndex(blobPath)
	if err != nil {
		return nil, err
	}

	blobsUsedInImageRefIndex := make(map[digest.Digest]int)
	err = ref.getBlobsUsedInIndex(blobsUsedInImageRefIndex, index)
	if err != nil {
		return nil, err
	}
	blobsUsedInImageRefIndex[descriptor.Digest]++ // Add the nested index in the list of blobs used by this reference

	return blobsUsedInImageRefIndex, nil
}

// Returns a map of digest with the usage count, so a blob that is referenced three times will have 3 in the map
func (ref ociReference) getBlobsUsedInIndex(destination map[digest.Digest]int, index *imgspecv1.Index) error {
	for _, descriptor := range index.Manifests {
		destination[descriptor.Digest]++
		switch descriptor.MediaType {
		case imgspecv1.MediaTypeImageManifest:
			manifest, err := ref.getManifest(&descriptor)
			if err != nil {
				return err
			}
			for digest, count := range ref.getBlobsUsedInManifest(manifest) {
				destination[digest] += count
			}
		case imgspecv1.MediaTypeImageIndex:
			blobPath, err := ref.blobPath(descriptor.Digest, "")
			if err != nil {
				return err
			}
			index, err := parseIndex(blobPath)
			if err != nil {
				return err
			}
			err = ref.getBlobsUsedInIndex(destination, index)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported mediaType in index: %q", descriptor.MediaType)
		}
	}

	return nil
}

func (ref ociReference) getBlobsUsedInManifest(manifest *imgspecv1.Manifest) map[digest.Digest]int {
	blobsUsedInManifest := make(map[digest.Digest]int, 0)

	blobsUsedInManifest[manifest.Config.Digest]++
	for _, layer := range manifest.Layers {
		blobsUsedInManifest[layer.Digest]++
	}

	return blobsUsedInManifest
}

// This takes in a map of the digest and their usage count in the manifest to be deleted
// It will compare it to the digest usage in the root index, and return a set of the blobs that can be safely deleted
func (ref ociReference) getBlobsToDelete(blobsUsedByDescriptorToDelete map[digest.Digest]int) (*set.Set[digest.Digest], error) {
	rootIndex, err := ref.getIndex()
	if err != nil {
		return nil, err
	}
	blobsUsedInRootIndex := make(map[digest.Digest]int)
	err = ref.getBlobsUsedInIndex(blobsUsedInRootIndex, rootIndex)
	if err != nil {
		return nil, err
	}

	blobsToDelete := set.New[digest.Digest]()

	for digest, count := range blobsUsedInRootIndex {
		if count-blobsUsedByDescriptorToDelete[digest] == 0 {
			blobsToDelete.Add(digest)
		}
	}

	return blobsToDelete, nil
}

func (ref ociReference) deleteBlobs(blobsToDelete *set.Set[digest.Digest]) error {
	for _, digest := range blobsToDelete.Values() {
		blobPath, err := ref.blobPath(digest, "") //Only delete in the local directory, not in the shared blobs path
		if err != nil {
			return err
		}
		err = deleteBlob(blobPath)
		if err != nil {
			return err
		}
	}

	return nil
}

func deleteBlob(blobPath string) error {
	logrus.Debug(fmt.Sprintf("Deleting blob at %q", blobPath))

	err := os.Remove(blobPath)
	if err != nil {
		if os.IsNotExist(err) {
			logrus.Info(fmt.Sprintf("Blob at %q not found; it was either previously deleted or is in the shared blobs directory", blobPath))
			return nil
		} else {
			return err
		}
	} else {
		return nil
	}
}

func (ref ociReference) deleteReferenceFromIndex() error {
	index, err := ref.getIndex()
	if err != nil {
		return err
	}

	if ref.image == "" && len(index.Manifests) == 1 {
		index.Manifests = make([]imgspecv1.Descriptor, 0)
		return saveJSON(ref.indexPath(), index)
	}

	newDescriptors := make([]imgspecv1.Descriptor, 0, len(index.Manifests)-1)
	for _, descriptor := range index.Manifests {
		if descriptor.Annotations[imgspecv1.AnnotationRefName] != ref.image {
			newDescriptors = append(newDescriptors, descriptor)
		}
	}
	index.Manifests = newDescriptors

	return saveJSON(ref.indexPath(), index)
}

func saveJSON(path string, content any) error {
	// If the file already exists, get its mode to preserve it
	var mode fs.FileMode
	existingfi, err := os.Stat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		} else { // File does not exist, use default mode
			mode = 0644
		}
	} else {
		mode = existingfi.Mode()
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer file.Close()

	return json.NewEncoder(file).Encode(content)
}

func (ref ociReference) getManifest(descriptor *imgspecv1.Descriptor) (*imgspecv1.Manifest, error) {
	manifestPath, err := ref.blobPath(descriptor.Digest, "")
	if err != nil {
		return nil, err
	}

	manifest, err := parseJSON[imgspecv1.Manifest](manifestPath)
	if err != nil {
		return nil, err
	}

	return manifest, nil
}
