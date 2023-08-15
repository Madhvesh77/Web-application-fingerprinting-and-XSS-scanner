from django.shortcuts import render

# Create your views here.
def page1(request):
    return render(request, 'page1.html')

def page2(request):
    name = request.GET['inputname']
    return render(request, 'page2.html', {'name':name})

def page3(request):
    return render(request, 'page3.html')

def page4(request):
    inputname = request.GET['inputname']
    return render(request, 'page4.html', {'name':inputname})