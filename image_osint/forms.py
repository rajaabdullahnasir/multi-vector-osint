from django import forms


class ImageUploadForm(forms.Form):
    image = forms.ImageField(
        label="Image file",
        help_text="JPG, PNG, TIFF, or WebP — maximum 10MB.",
        required=True,
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["image"].widget.attrs.update(
            {
                "class": "ov-dropzone__input",
                "accept": "image/jpeg,image/png,image/tiff,image/webp,.jpg,.jpeg,.png,.tif,.tiff,.webp",
                "data-dropzone-input": "true",
            }
        )
