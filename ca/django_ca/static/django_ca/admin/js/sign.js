// see https://docs.djangoproject.com/en/1.9/ref/csrf/#ajax
function getCookie(name) {
    var cookieValue = null;
    if (document.cookie && document.cookie != '') {
        var cookies = document.cookie.split(';');
        for (var i = 0; i < cookies.length; i++) {
            var cookie = django.jQuery.trim(cookies[i]);
            // Does this cookie string begin with the name we want?
            if (cookie.substring(0, name.length + 1) == (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}
var csrftoken = getCookie('csrftoken');

function csrfSafeMethod(method) {
    // these HTTP methods do not require CSRF protection
    return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
}
django.jQuery.ajaxSetup({
    beforeSend: function(xhr, settings) {
        if (!csrfSafeMethod(settings.type) && !this.crossDomain) {
            xhr.setRequestHeader("X-CSRFToken", csrftoken);
        }
    }
});

django.jQuery(document).ready(function() {
    django.jQuery('.field-csr textarea').bind('input', function() {
        var value = django.jQuery(this).val();

        if (! (value.startsWith('-----BEGIN CERTIFICATE REQUEST-----\n')
               && value.endsWith('\n-----END CERTIFICATE REQUEST-----'))) {
            console.log('not a valid csr');
            return;
        }

        django.jQuery.post('/admin/django_ca/certificate/ajax/csr-details', {
            'csr': value,
        }).done(function(data) {
            // populate CN/E, if they are currently empty
            var cn = django.jQuery('.field-subject #commonname input');
            if (! cn.val() && data.subject.CN) {
                cn.val(data.subject.CN);
            }
            var email = django.jQuery('.field-subject #e-mail input');
            if (! email.val() && data.subject.E) {
                email.val(data.subject.E);
            }
        });
    });
});
