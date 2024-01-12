from django.shortcuts import render, get_object_or_404
from django.views import generic
from django.contrib.auth.forms import UserCreationForm, UserChangeForm, PasswordChangeForm
from django.contrib import messages
from django.shortcuts import redirect
from django.urls import reverse_lazy
from .forms import SignupForm, EditProfileForm, PasswordChangingForm, ProfilePageForm, VerifyOTPForm
from django.contrib.auth.views import PasswordChangeView as BasePasswordChangeView
from django.views.generic import DetailView,FormView
from blogapp.models import Profile
from django.views.generic.edit import CreateView
from django.contrib.auth.views import PasswordChangeView,LoginView
from django.contrib.auth.models import User 



# class PasswordChangeView(PasswordChangeView):
#     form_class = PasswordChangingForm
#     # form_class = PasswordChangeForm
#     success_url = reverse_lazy('password_success')

class CreateProfilePageView(CreateView):
    model = Profile
    form_class = ProfilePageForm
    template_name = 'registration/create_user_profile_page.html'
    # fields = '__all__'

    def form_valid(self, form):
        form.instance.user = self.request.user
        return super().form_valid(form)



class EditProfilePageView(generic.UpdateView):
    model = Profile 
    template_name = 'registration/edit_profile_page.html'
    fields = ['bio','profile_pic','website_url','facebook_url','twitter_url','instagram_url','pinterest_url']


    success_url = reverse_lazy('home')


class ShowProfilePageView(DetailView):
    model = Profile
    template_name = 'registration/user_profile.html'

    def get_context_data(self, *args, **kwargs):
        # users = Profile.objects.all()
        context = super(ShowProfilePageView, self).get_context_data(*args, **kwargs)

        page_user = get_object_or_404(Profile, id=self.kwargs['pk'])
        context["page_user"] = page_user
        return context


class PasswordChangeView(BasePasswordChangeView):
    form_class = PasswordChangingForm
    success_url = reverse_lazy('password_success')

def password_success(request):
    return render(request, 'registration/password_success.html', {})

class UserRegisterView(CreateView):
    form_class = SignupForm
    template_name = 'registration/register.html'
    success_url = reverse_lazy('login')

    def form_valid(self, form):
        if 'send_otp' in self.request.POST:
            email = form.cleaned_data['email']
            if email:
                otp = form.send_otp(email)
                form.cleaned_data['otp'] = otp
                # Store the user's registration data in the session for later use
                self.request.session['registration_data'] = form.cleaned_data
                return redirect('verify_otp')  # Redirect to the OTP verification page
        return super().form_valid(form)

class VerifyOTPView(FormView):
    form_class = VerifyOTPForm
    template_name = 'registration/verify_otp.html'
    success_url = reverse_lazy('login')

    def dispatch(self, request, *args, **kwargs):
        self.user = request.user
        self.form = self.get_form()
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        otp_entered_by_user = form.cleaned_data.get('otp')
        stored_otp = self.request.session.get('registration_otp')

        if stored_otp and otp_entered_by_user == stored_otp:
            registration_data = self.request.session.get('registration_data')
            if registration_data:
                user = User.objects.create_user(
                    username=registration_data['username'],
                    email=registration_data['email'],
                    password=registration_data['password'],
                )

                # Authenticate the user after successful registration
                auth_user = authenticate(
                    username=registration_data['username'],
                    password=registration_data['password'],
                )

                if auth_user:
                    login(self.request, auth_user)  # Log the user in
                    messages.success(self.request, 'Your account has been successfully registered and you are now logged in.')
                    return redirect('home')
        else:
            messages.error(self.request, 'Invalid OTP. Please try again.')

        return super().form_valid(form)


class UserLoginView(LoginView):
    template_name = 'registration/login.html'  # Provide the path to your login template
    success_url = reverse_lazy('home')  # Redirect to the home page upon successful login



class UserEditView(generic.UpdateView):
    form_class = EditProfileForm
    template_name = 'registration/edit_profile.html'
    success_url = reverse_lazy('home')

    def get_object(self):
        return self.request.user
