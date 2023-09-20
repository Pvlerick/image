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
	sharedBlobsDir := ""
	if sys != nil && sys.OCISharedBlobDirPath != "" {
		sharedBlobsDir = sys.OCISharedBlobDirPath
	}

	desciptor, err := ref.getManifestDescriptor()
	if err != nil {
		return err
	}

	switch desciptor.MediaType {
	case imgspecv1.MediaTypeImageManifest:
		return ref.deleteSingleImage(desciptor, sharedBlobsDir)
	case imgspecv1.MediaTypeImageIndex:
		return ref.deleteImageIndex(desciptor, sharedBlobsDir)
	default:
		return fmt.Errorf("unsupported mediaType in index")
	}
}

func (ref ociReference) deleteSingleImage(desciptor imgspecv1.Descriptor, sharedBlobsDir string) error {
	manifest, err := ref.getManifest(&desciptor, sharedBlobsDir)
	if err != nil {
		return err
	}
	blobsUsedInManifest := ref.getBlobsUsedInManifest(*manifest)
	blobsUsedInManifest[desciptor.Digest]++ // Add the current manifest to the list of blobs used by this reference

	blobsToDelete, err := ref.getBlobsToDelete(blobsUsedInManifest, sharedBlobsDir)
	if err != nil {
		return err
	}

	err = ref.deleteBlobs(blobsToDelete)
	if err != nil {
		return err
	}

	return ref.deleteReferenceFromIndex()
}

func (ref ociReference) deleteImageIndex(desciptor imgspecv1.Descriptor, sharedBlobsDir string) error {
	blobPath, err := ref.blobPath(desciptor.Digest, sharedBlobsDir)
	if err != nil {
		return err
	}
	index, err := parseIndex(blobPath)
	if err != nil {
		return err
	}

	blobsUsedInImageRefIndex, err := ref.getBlobsUsedInIndex(index, sharedBlobsDir)
	if err != nil {
		return err
	}
	blobsUsedInImageRefIndex[desciptor.Digest]++ // Add the nested index in the list of blobs used by this reference

	blobsToDelete, err := ref.getBlobsToDelete(blobsUsedInImageRefIndex, sharedBlobsDir)
	if err != nil {
		return err
	}

	err = ref.deleteBlobs(blobsToDelete)
	if err != nil {
		return err
	}

	return ref.deleteReferenceFromIndex()
}

// Returns a map of digest with the usage count, so a blob that is referenced three times will have 3 in the map
func (ref ociReference) getBlobsUsedInIndex(index *imgspecv1.Index, sharedBlobsDir string) (map[digest.Digest]int, error) {
	blobsUsedInIndex := make(map[digest.Digest]int)
	for _, desciptor := range index.Manifests {
		blobsUsedInIndex[desciptor.Digest]++
		switch desciptor.MediaType {
		case imgspecv1.MediaTypeImageManifest:
			manifest, err := ref.getManifest(&desciptor, sharedBlobsDir)
			if err != nil {
				return nil, err
			}
			for digest, count := range ref.getBlobsUsedInManifest(*manifest) {
				blobsUsedInIndex[digest] += count
			}
		case imgspecv1.MediaTypeImageIndex:
			blobPath, err := ref.blobPath(desciptor.Digest, sharedBlobsDir)
			if err != nil {
				return nil, err
			}
			index, err := parseIndex(blobPath)
			if err != nil {
				return nil, err
			}
			blobsUsedInNestedIndex, err := ref.getBlobsUsedInIndex(index, sharedBlobsDir)
			if err != nil {
				return nil, err
			}
			for k, v := range blobsUsedInNestedIndex {
				blobsUsedInIndex[k] = blobsUsedInIndex[k] + v
			}
		default:
			return nil, fmt.Errorf("unsupported mediaType in index")
		}
	}

	return blobsUsedInIndex, nil
}

func (ref ociReference) getBlobsUsedInManifest(manifest imgspecv1.Manifest) map[digest.Digest]int {
	blobsUsedInManifest := make(map[digest.Digest]int, 0)
	blobsUsedInManifest[manifest.Config.Digest]++
	for _, layer := range manifest.Layers {
		blobsUsedInManifest[layer.Digest]++
	}
	return blobsUsedInManifest
}

func (ref ociReference) getBlobsToDelete(blobsUsedByDescriptorToDelete map[digest.Digest]int, sharedBlobsDir string) (*set.Set[digest.Digest], error) {
	rootIndex, err := ref.getIndex()
	if err != nil {
		return nil, err
	}
	blobsUsedInRootIndex, err := ref.getBlobsUsedInIndex(rootIndex, sharedBlobsDir)
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
		_, err = os.Stat(blobPath)
		if err == nil {
			logrus.Debug("Deleting blob ", digest.Hex())
			err = os.Remove(blobPath)
			if err != nil && !os.IsNotExist(err) {
				return err
			}
		} else {
			if os.IsNotExist(err) {
				logrus.Info("Blob ", digest.Hex(), " not found in image directory; it was either previously deleted or is in the shared blobs directory")
			} else {
				return err
			}
		}
	}

	return nil
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

	// Then write the file
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer file.Close()

	return json.NewEncoder(file).Encode(content)
}

func (ref ociReference) getManifest(descriptor *imgspecv1.Descriptor, sharedBlobsDir string) (*imgspecv1.Manifest, error) {
	manifestPath, err := ref.blobPath(descriptor.Digest, sharedBlobsDir)
	if err != nil {
		return nil, err
	}

	manifest, err := parseJSON[imgspecv1.Manifest](manifestPath)
	if err != nil {
		return nil, err
	}

	return manifest, nil
}
