package layout

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/containers/image/v5/directory/explicitfilepath"
	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/internal/image"
	"github.com/containers/image/v5/internal/set"
	"github.com/containers/image/v5/oci/internal"
	"github.com/containers/image/v5/transports"
	"github.com/containers/image/v5/types"
	"github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
)

func init() {
	transports.Register(Transport)
}

var (
	// Transport is an ImageTransport for OCI directories.
	Transport = ociTransport{}

	// ErrMoreThanOneImage is an error returned when the manifest includes
	// more than one image and the user should choose which one to use.
	ErrMoreThanOneImage = errors.New("more than one image in oci, choose an image")
)

type ociTransport struct{}

func (t ociTransport) Name() string {
	return "oci"
}

// ParseReference converts a string, which should not start with the ImageTransport.Name prefix, into an ImageReference.
func (t ociTransport) ParseReference(reference string) (types.ImageReference, error) {
	return ParseReference(reference)
}

// ValidatePolicyConfigurationScope checks that scope is a valid name for a signature.PolicyTransportScopes keys
// (i.e. a valid PolicyConfigurationIdentity() or PolicyConfigurationNamespaces() return value).
// It is acceptable to allow an invalid value which will never be matched, it can "only" cause user confusion.
// scope passed to this function will not be "", that value is always allowed.
func (t ociTransport) ValidatePolicyConfigurationScope(scope string) error {
	return internal.ValidateScope(scope)
}

// ociReference is an ImageReference for OCI directory paths.
type ociReference struct {
	// Note that the interpretation of paths below depends on the underlying filesystem state, which may change under us at any time!
	// Either of the paths may point to a different, or no, inode over time.  resolvedDir may contain symbolic links, and so on.

	// Generally we follow the intent of the user, and use the "dir" member for filesystem operations (e.g. the user can use a relative path to avoid
	// being exposed to symlinks and renames in the parent directories to the working directory).
	// (But in general, we make no attempt to be completely safe against concurrent hostile filesystem modifications.)
	dir         string // As specified by the user. May be relative, contain symlinks, etc.
	resolvedDir string // Absolute path with no symlinks, at least at the time of its creation. Primarily used for policy namespaces.
	// If image=="", it means the "only image" in the index.json is used in the case it is a source
	// for destinations, the image name annotation "image.ref.name" is not added to the index.json
	image string
}

// ParseReference converts a string, which should not start with the ImageTransport.Name prefix, into an OCI ImageReference.
func ParseReference(reference string) (types.ImageReference, error) {
	dir, image := internal.SplitPathAndImage(reference)
	return NewReference(dir, image)
}

// NewReference returns an OCI reference for a directory and a image.
//
// We do not expose an API supplying the resolvedDir; we could, but recomputing it
// is generally cheap enough that we prefer being confident about the properties of resolvedDir.
func NewReference(dir, image string) (types.ImageReference, error) {
	resolved, err := explicitfilepath.ResolvePathToFullyExplicit(dir)
	if err != nil {
		return nil, err
	}

	if err := internal.ValidateOCIPath(dir); err != nil {
		return nil, err
	}

	if err = internal.ValidateImageName(image); err != nil {
		return nil, err
	}

	return ociReference{dir: dir, resolvedDir: resolved, image: image}, nil
}

func (ref ociReference) Transport() types.ImageTransport {
	return Transport
}

// StringWithinTransport returns a string representation of the reference, which MUST be such that
// reference.Transport().ParseReference(reference.StringWithinTransport()) returns an equivalent reference.
// NOTE: The returned string is not promised to be equal to the original input to ParseReference;
// e.g. default attribute values omitted by the user may be filled in the return value, or vice versa.
// WARNING: Do not use the return value in the UI to describe an image, it does not contain the Transport().Name() prefix.
func (ref ociReference) StringWithinTransport() string {
	return fmt.Sprintf("%s:%s", ref.dir, ref.image)
}

// DockerReference returns a Docker reference associated with this reference
// (fully explicit, i.e. !reference.IsNameOnly, but reflecting user intent,
// not e.g. after redirect or alias processing), or nil if unknown/not applicable.
func (ref ociReference) DockerReference() reference.Named {
	return nil
}

// PolicyConfigurationIdentity returns a string representation of the reference, suitable for policy lookup.
// This MUST reflect user intent, not e.g. after processing of third-party redirects or aliases;
// The value SHOULD be fully explicit about its semantics, with no hidden defaults, AND canonical
// (i.e. various references with exactly the same semantics should return the same configuration identity)
// It is fine for the return value to be equal to StringWithinTransport(), and it is desirable but
// not required/guaranteed that it will be a valid input to Transport().ParseReference().
// Returns "" if configuration identities for these references are not supported.
func (ref ociReference) PolicyConfigurationIdentity() string {
	// NOTE: ref.image is not a part of the image identity, because "$dir:$someimage" and "$dir:" may mean the
	// same image and the two can’t be statically disambiguated.  Using at least the repository directory is
	// less granular but hopefully still useful.
	return ref.resolvedDir
}

// PolicyConfigurationNamespaces returns a list of other policy configuration namespaces to search
// for if explicit configuration for PolicyConfigurationIdentity() is not set.  The list will be processed
// in order, terminating on first match, and an implicit "" is always checked at the end.
// It is STRONGLY recommended for the first element, if any, to be a prefix of PolicyConfigurationIdentity(),
// and each following element to be a prefix of the element preceding it.
func (ref ociReference) PolicyConfigurationNamespaces() []string {
	res := []string{}
	path := ref.resolvedDir
	for {
		lastSlash := strings.LastIndex(path, "/")
		// Note that we do not include "/"; it is redundant with the default "" global default,
		// and rejected by ociTransport.ValidatePolicyConfigurationScope above.
		if lastSlash == -1 || path == "/" {
			break
		}
		res = append(res, path)
		path = path[:lastSlash]
	}
	return res
}

// NewImage returns a types.ImageCloser for this reference, possibly specialized for this ImageTransport.
// The caller must call .Close() on the returned ImageCloser.
// NOTE: If any kind of signature verification should happen, build an UnparsedImage from the value returned by NewImageSource,
// verify that UnparsedImage, and convert it into a real Image via image.FromUnparsedImage.
// WARNING: This may not do the right thing for a manifest list, see image.FromSource for details.
func (ref ociReference) NewImage(ctx context.Context, sys *types.SystemContext) (types.ImageCloser, error) {
	return image.FromReference(ctx, sys, ref)
}

// getIndex returns a pointer to the index references by this ociReference. If an error occurs opening an index nil is returned together
// with an error.
func (ref ociReference) getIndex() (*imgspecv1.Index, error) {
	return parseIndex(ref.indexPath())
}

func parseJSON[T any](path string) (*T, error) {
	content, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer content.Close()

	obj := new(T)
	if err := json.NewDecoder(content).Decode(obj); err != nil {
		return nil, err
	}
	return obj, nil
}

func parseIndex(path string) (*imgspecv1.Index, error) {
	return parseJSON[imgspecv1.Index](path)
}

func (ref ociReference) getManifestDescriptor() (imgspecv1.Descriptor, error) {
	index, err := ref.getIndex()
	if err != nil {
		return imgspecv1.Descriptor{}, err
	}

	if ref.image == "" {
		// return manifest if only one image is in the oci directory
		if len(index.Manifests) != 1 {
			// ask user to choose image when more than one image in the oci directory
			return imgspecv1.Descriptor{}, ErrMoreThanOneImage
		}
		return index.Manifests[0], nil
	} else {
		// if image specified, look through all manifests for a match
		var unsupportedMIMETypes []string
		for _, md := range index.Manifests {
			if refName, ok := md.Annotations[imgspecv1.AnnotationRefName]; ok && refName == ref.image {
				if md.MediaType == imgspecv1.MediaTypeImageManifest || md.MediaType == imgspecv1.MediaTypeImageIndex {
					return md, nil
				}
				unsupportedMIMETypes = append(unsupportedMIMETypes, md.MediaType)
			}
		}
		if len(unsupportedMIMETypes) != 0 {
			return imgspecv1.Descriptor{}, fmt.Errorf("reference %q matches unsupported manifest MIME types %q", ref.image, unsupportedMIMETypes)
		}
	}
	return imgspecv1.Descriptor{}, ImageNotFoundError{ref}
}

// Stores an (image) descriptor along with the index it was found in and its parents if any
// this allows the update of the index when an image is located in a nested (++) index
type descriptorWrapper struct {
	descriptor *imgspecv1.Descriptor
	indexChain []string //in order of appearence, the first is always be index.json and the nested indexes, last one being the one where the descriptor was found in
}

// This will return all the descriptors of all the images found in the directory
// It starts at the index.json and then walks all nested indexes
// Each image descriptor is returned along with the index it was found, as well as it parents if it is a nested index
func (ref ociReference) getAllImageDescriptorsInDirectory() ([]descriptorWrapper, error) {
	descriptors := make([]descriptorWrapper, 0)
	var getImageDescriptorsFromIndex func(indexChain []string) error
	getImageDescriptorsFromIndex = func(indexChain []string) error {
		index, err := parseIndex(indexChain[len(indexChain)-1]) // last item in the index is always the index in which whe are currently working
		if err != nil {
			return err
		}

		for _, manifestDescriptor := range index.Manifests {
			switch manifestDescriptor.MediaType {
			case imgspecv1.MediaTypeImageManifest:
				tmpManifestDescriptor := manifestDescriptor
				wrapper := descriptorWrapper{&tmpManifestDescriptor, indexChain}
				descriptors = append(descriptors, wrapper)
			case imgspecv1.MediaTypeImageIndex:
				nestedIndexBlobPath, err := ref.blobPath(manifestDescriptor.Digest, "")
				if err != nil {
					return err
				}
				// recursively get manifests from this nested index
				err = getImageDescriptorsFromIndex(append(indexChain, nestedIndexBlobPath))
				if err != nil {
					return err
				}
			}
		}
		return nil
	}

	err := getImageDescriptorsFromIndex([]string{ref.indexPath()}) //Start the walk at the root (index.json)
	return descriptors, err
}

func (ref ociReference) getManifest(descriptor *imgspecv1.Descriptor) (*imgspecv1.Manifest, error) {
	//TODO Check if there is shared blob path?
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

// LoadManifestDescriptor loads the manifest descriptor to be used to retrieve the image name
// when pulling an image
func LoadManifestDescriptor(imgRef types.ImageReference) (imgspecv1.Descriptor, error) {
	ociRef, ok := imgRef.(ociReference)
	if !ok {
		return imgspecv1.Descriptor{}, errors.New("error typecasting, need type ociRef")
	}
	return ociRef.getManifestDescriptor()
}

// NewImageSource returns a types.ImageSource for this reference.
// The caller must call .Close() on the returned ImageSource.
func (ref ociReference) NewImageSource(ctx context.Context, sys *types.SystemContext) (types.ImageSource, error) {
	return newImageSource(sys, ref)
}

// NewImageDestination returns a types.ImageDestination for this reference.
// The caller must call .Close() on the returned ImageDestination.
func (ref ociReference) NewImageDestination(ctx context.Context, sys *types.SystemContext) (types.ImageDestination, error) {
	return newImageDestination(sys, ref)
}

type indexUpdateStep struct {
	action    string
	digest    digest.Digest
	newDigest *digest.Digest
}

// DeleteImage deletes the named image from the directory, if supported.
func (ref ociReference) DeleteImage(ctx context.Context, sys *types.SystemContext) error {
	// Scan all the manifests in the directory:
	// ... collect the one that matches with the received ref
	// ... and store all the blobs used in all other images
	var imageDescriptorWrapper *descriptorWrapper
	blobsUsedByOtherImages := set.New[digest.Digest]()
	allDescriptors, err := ref.getAllImageDescriptorsInDirectory()
	if err != nil {
		return err
	}

	if ref.image == "" {
		if len(allDescriptors) == 1 {
			imageDescriptorWrapper = &allDescriptors[0]
		} else {
			return ErrMoreThanOneImage
		}
	} else {
		for _, v := range allDescriptors {
			if v.descriptor.Annotations[imgspecv1.AnnotationRefName] == ref.image {
				tmpDescriptionWrapper := v
				imageDescriptorWrapper = &tmpDescriptionWrapper
			} else {
				otherImageManifest, err := ref.getManifest(v.descriptor)
				if err != nil {
					return err
				}
				blobsUsedByOtherImages.Add(otherImageManifest.Config.Digest)
				for _, layer := range otherImageManifest.Layers {
					blobsUsedByOtherImages.Add(layer.Digest)
				}
			}
		}
	}

	if ref.image != "" && imageDescriptorWrapper == nil {
		return ImageNotFoundError{ref}
	}

	manifest, err := ref.getManifest(imageDescriptorWrapper.descriptor)
	if err != nil {
		return err
	}

	// Delete all blobs used by this image only
	blobsToDelete := set.New[digest.Digest]()
	for _, descriptor := range append(manifest.Layers, manifest.Config, *imageDescriptorWrapper.descriptor) {
		if !blobsUsedByOtherImages.Contains(descriptor.Digest) {
			blobsToDelete.Add(descriptor.Digest)
		} else {
			logrus.Debug("Blob ", descriptor.Digest.Hex(), " is used by another image, leaving it")
		}
	}
	for _, digest := range blobsToDelete.Values() {
		//TODO Check if there is shared blob path?
		blobPath, err := ref.blobPath(digest, "")
		if err != nil {
			return err
		}
		logrus.Debug("Deleting blob ", digest.Hex())
		err = os.Remove(blobPath)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
	}

	// This holds the step to be done on the current index, as we walk back bottom up
	step := indexUpdateStep{"delete", imageDescriptorWrapper.descriptor.Digest, nil}

	for i := len(imageDescriptorWrapper.indexChain) - 1; i >= 0; i-- {
		indexPath := imageDescriptorWrapper.indexChain[i]
		index, err := parseIndex(indexPath)
		if err != nil {
			return err
		}
		// Fill new index with existing manifests except the one we are removing
		newManifests := make([]imgspecv1.Descriptor, 0, len(index.Manifests))
		for _, v := range index.Manifests {
			if v.Digest == step.digest {
				switch step.action {
				case "delete":
					continue
				case "update":
					newDescriptor := v
					newDescriptor.Digest = *step.newDigest
					newManifests = append(newManifests, newDescriptor)
				}
			} else {
				newManifests = append(newManifests, v)
			}
		}
		index.Manifests = newManifests

		// New index is ready, it has to be saved to disk now
		// ... if it is the root index, it's easy, just overwrite it
		if indexPath == ref.indexPath() {
			return saveJSON(ref.indexPath(), index)
		} else {
			indexDigest, err := digest.Parse("sha256:" + filepath.Base(indexPath))
			if err != nil {
				return err
			}
			// In a nested index, if the new index is empty it has to be remove,
			// otherwise update the parent index with the new hash
			if len(index.Manifests) == 0 {
				step = indexUpdateStep{"delete", indexDigest, nil}
			} else {
				// Save the new file
				buffer := new(bytes.Buffer)
				err = json.NewEncoder(buffer).Encode(index)
				if err != nil {
					return err
				}
				indexNewDigest := digest.Canonical.FromBytes(buffer.Bytes())
				indexNewPath, err := ref.blobPath(indexNewDigest, "")
				if err != nil {
					return err
				}
				err = saveJSON(indexNewPath, index)
				if err != nil {
					return err
				}
				step = indexUpdateStep{"update", indexDigest, &indexNewDigest}
			}
			// Delete the current index if it is not reference anywhere else;
			// it is dangling by now as it'll either be empty or have a new hash
			if !blobsUsedByOtherImages.Contains(indexDigest) {
				err = os.Remove(indexPath)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
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

// ociLayoutPath returns a path for the oci-layout within a directory using OCI conventions.
func (ref ociReference) ociLayoutPath() string {
	return filepath.Join(ref.dir, imgspecv1.ImageLayoutFile)
}

// indexPath returns a path for the index.json within a directory using OCI conventions.
func (ref ociReference) indexPath() string {
	return filepath.Join(ref.dir, imgspecv1.ImageIndexFile)
}

// blobPath returns a path for a blob within a directory using OCI image-layout conventions.
func (ref ociReference) blobPath(digest digest.Digest, sharedBlobDir string) (string, error) {
	if err := digest.Validate(); err != nil {
		return "", fmt.Errorf("unexpected digest reference %s: %w", digest, err)
	}
	var blobDir string
	if sharedBlobDir != "" {
		blobDir = sharedBlobDir
	} else {
		blobDir = filepath.Join(ref.dir, imgspecv1.ImageBlobsDir)
	}
	return filepath.Join(blobDir, digest.Algorithm().String(), digest.Hex()), nil
}
