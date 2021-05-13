from django import forms


from authentication.widgets import SelectDateWidget
from authentication.models import *
# from customer.models import Customer
# from authentication.models import EmployeeMaster, EmployeeMasterCustomer
#from authentication.models import EmployeeMaster

# CUSTOMERS = [(c.id, c.name) for c in Customer.objects.all()]
CUSTOMERS = [1,'saroj']

LOGIN_CHOICES = (
    (0, 'False'),
    (1, 'True')
)

class EmployeeMasterForm(forms.ModelForm):
    customer = forms.MultipleChoiceField(choices=CUSTOMERS, widget=forms.SelectMultiple, required=False)
    query_limit = forms.CharField(max_length=5, label='Query Limit (Default 500)', required=False)

    def __init__(self, *args, **kwargs):
        super(EmployeeMasterForm, self).__init__(*args, **kwargs)
        self.fields['service_centre'] = forms.ModelChoiceField(queryset=DistributionCenter.objects.filter(),
                empty_label="Select Service Centre (Required)", required=False)

        for field_name in self.fields:
            field = self.fields.get(field_name)
            if field:
                if type(field.widget) in (forms.TextInput, forms.DateInput):
                    if field.required:
                      field.widget = forms.TextInput(attrs={'placeholder': field.label+' (required)'})
                    else:
                      field.widget = forms.TextInput(attrs={'placeholder': field.label})
        # while form is editing prefill form with customers multiselect box
        instance = kwargs.get('instance')

        if instance:
            customers = [e.customer.pk for e in EmployeeMasterCustomer.objects.filter(employee_master=instance)]
            self.fields['customer'].initial = customers

    class Meta:
        model = EmployeeMaster
        fields = ('employee_code', 'firstname', 'lastname', 'role', 'department',
                'customer', 'email','mobile_number', 'allow_concurent_login', 'query_limit')#, 'ebs', 'ebs_customer')

    def save(self, commit=True):
        instance = super(EmployeeMasterForm, self).save(commit=False)

        if commit:
            customer_ids = self.cleaned_data.get('customer')
            email = self.cleaned_data.get('email')
            password = self.cleaned_data.get('employee_code')

            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                user = User.objects.create_user(username=email,email=email,password=password)

            instance.user = user
            instance.save()

            for cid in customer_ids:
                if int(cid) == 0:
                    continue
                cust = Customer.objects.get(pk=int(cid))
                EmployeeMasterCustomer.objects.create(customer=cust, employee_master=instance)

        return instance

class OutscanEmployeeForm(forms.ModelForm):
    class Meta:
        model = EmployeeMaster
        exclude = ('user', 'customer', 'email',
                'mobile_number','login_active','staff_status')


class EmpregisterForm(forms.Form):
    first_name = models.CharField(max_length=50,blank= False)
    last_name = models.CharField(max_length=50,null= True, blank= True)
    mobile_no = models.GenericIPAddressField(max_length=50,blank= False)
    email = models.CharField(max_length=50,null= True, blank= True)
    is_active = models.BooleanField(default=False)


    def clean(self):
        cleaned_data = super(EmpregisterForm, self).clean()
        return cleaned_data



class PhotoForm(forms.ModelForm):
	class Meta:
		model = Photo
		fields = '__all__'

class PasswordResetRequestForm(forms.Form):
    email_or_username = forms.CharField(label=("Email Or Username"), max_length=254)

class SetPasswordForm(forms.Form):
    """
    A form that lets a user change set their password without entering the old
    password
    """
    error_messages = {
        'password_mismatch': ("The two password fields didn't match."),
        }
    new_password1 = forms.CharField(label=("New password"),
                                    widget=forms.PasswordInput)
    new_password2 = forms.CharField(label=("New password confirmation"),
                                    widget=forms.PasswordInput)

    def clean_new_password2(self):
        password1 = self.cleaned_data.get('new_password1')
        password2 = self.cleaned_data.get('new_password2')
        if password1 and password2:
            if password1 != password2:
                raise forms.ValidationError(
                    self.error_messages['password_mismatch'],
                    code='password_mismatch',
                    )
        return password2
