from flask import Flask, render_template,redirect,Blueprint,request
from flask_login import login_required
from cuba import db
from cuba.models import Todo


main = Blueprint('main',__name__)

# Create your views here.

#-------------------------General(Dashboards,Widgets & Layout)---------------------------------------

#---------------Dashboards



@main.route('/')
@main.route('/index')
@login_required
def index():
    context = { "breadcrumb":{"parent":"Dashboard","child":"Default","jsFunction":'startTime()'}}
    return render_template("general/dashboard/default/index.html",**context)


@main.route('/dashboard_02')
@login_required
def dashboard_02():
    context = {"breadcrumb":{"title":"E-Commerce","parent":"Dashboard", "child":"E-Commerce"}}    
    return render_template("general/dashboard/dashboard-02.html",**context)

@main.route('/online_course')
@login_required
def online_course():
    context = {"breadcrumb":{"title":"Online Course","parent":"Dashboard", "child":"Online Course"}} 
    return render_template("general/dashboard/dashboard-03.html",**context)

@main.route('/crypto')
@login_required
def crypto():
    context = {"breadcrumb":{"title":"Crypto","parent":"Dashboard", "child":"Crypto"}} 
    return render_template("general/dashboard/dashboard-04.html",**context)

@main.route('/social')
@login_required
def social():
    context = {"breadcrumb":{"title":"Social","parent":"Dashboard", "child":"Social"}} 
    return render_template("general/dashboard/dashboard-05.html",**context)

@main.route('/NFT')
@login_required
def NFT():
    context = {"breadcrumb":{"title":"NFT","parent":"Dashboard", "child":"NFT"}} 
    return render_template("general/dashboard/dashboard-06.html",**context)

@main.route('/school_management')
@login_required
def school_management():
    context = {"breadcrumb":{"title":"School Management","parent":"Dashboard", "child":"School Management"}} 
    return render_template("general/dashboard/dashboard-07.html",**context)

@main.route('/POS')
@login_required
def POS():
    context = {"breadcrumb":{"title":"POS","parent":"Dashboard", "child":"POS"}} 
    return render_template("general/dashboard/dashboard-08.html",**context)

@main.route('/CRM')
@login_required
def CRM():
    context = {"breadcrumb":{"title":"CRM","parent":"Dashboard", "child":"CRM"}} 
    return render_template("general/dashboard/dashboard-09.html",**context)

@main.route('/Analytics')
@login_required
def Analytics():
    context = {"breadcrumb":{"title":"Analytics","parent":"Dashboard", "child":"Analytics"}} 
    return render_template("general/dashboard/dashboard-10.html",**context)

@main.route('/HR')
@login_required
def HR():
    context = {"breadcrumb":{"title":"HR Dashboard","parent":"Dashboard", "child":"HR Dashboard"}} 
    return render_template("general/dashboard/dashboard-11.html",**context)



#----------------Widgets
@main.route('/general_widget')
@login_required
def general_widget():
    context = {"breadcrumb":{"title":"General","parent":"Widgets", "child":"General"}} 
    return render_template("general/widget/general-widget.html",**context)
    

@main.route('/chart_widget')
@login_required
def chart_widget():
    context = {"breadcrumb":{"title":"Chart","parent":"Widgets", "child":"Chart"}} 
    return render_template("general/widget/chart-widget.html",**context)
    

# #-----------------Layout
@main.route('/box_layout')
@login_required
def box_layout():
    context = {'layout':'box-layout', "breadcrumb":{"title":"Box Layout","parent":"Page Layout", "child":"Box Layout"}}
    return render_template("general/page-layout/box-layout.html",**context)
    

@main.route('/layout_rtl')
@login_required
def layout_rtl():
    context = {'layout':'rtl', "breadcrumb":{"title":"RTL Layout","parent":"Page Layout", "child":"RTL Layout"}}
    return render_template("general/page-layout/layout-rtl.html",**context)
    
@main.route('/layout_dark')
@login_required
def layout_dark():
    context = {'layout':'dark-only', "breadcrumb":{"title":"Layout Dark","parent":"Page Layout", "child":"Layout Dark"}}
    return render_template("general/page-layout/layout-dark.html",**context)
    

@main.route('/hide_on_scroll')
@login_required
def hide_on_scroll():
    context = { "breadcrumb":{"title":"Hide Menu On Scroll","parent":"Page Layout", "child":"Hide Menu On Scroll"}}
    return render_template("general/page-layout/hide-on-scroll.html",**context)
    
@main.route('/footer_light')
@login_required
def footer_light():
    context = { "breadcrumb":{"title":"Footer light","parent":"Page Layout", "child":"Footer light"}}
    return render_template("general/page-layout/footer-light.html",**context)
    
@main.route('/footer_dark')
@login_required
def footer_dark():
    context = { "footer": "footer-dark", "breadcrumb":{"title":"Footer Dark","parent":"Page Layout", "child":"Footer Dark"}}
    return render_template("general/page-layout/footer-dark.html",**context)
    
@main.route('/footer_fixed')
@login_required
def footer_fixed():
    context = { "footer": "footer-fix", "breadcrumb":{"title":"Footer Fixed","parent":"Page Layout", "child":"Footer Fixed"}}
    return render_template("general/page-layout/footer-fixed.html",**context)


#--------------------------------Applications---------------------------------

#---------------------Project 

@main.route('/project_details')
@login_required
def project_details():
    context = { "breadcrumb":{"title":"Project Details","parent":"Projects", "child":"Project Details"}}
    return render_template("applications/projects/scope-project.html",**context)

@main.route('/project_list')
@login_required
def project_list():
    context = { "breadcrumb":{"title":"Project List","parent":"Projects", "child":"Project List"}}
    return render_template("applications/projects/project-list.html",**context)
    
@main.route('/projectcreate')
@login_required
def projectcreate():
    context = { "breadcrumb":{"title":"Project Create","parent":"Projects", "child":"Project Create"}}
    return render_template("applications/projects/projectcreate.html",**context)
    
#-------------------File Manager
@main.route('/file_manager')
@login_required
def file_manager():
    context = { "breadcrumb":{"title":"File Manager","parent":"Apps", "child":"File Manager"}}
    return render_template("applications/file-manager/file-manager.html",**context)
       

#------------------Kanban Board
@main.route('/kanban')
@login_required
def kanban():
    context = { "breadcrumb":{"title":"Kanban Board","parent":"Apps", "child":"Kanban Board"}}
    return render_template("applications/kanban/kanban.html",**context)
    


#------------------------ Ecommerce
@main.route('/add_products')
@login_required
def add_products():
    context = { "breadcrumb":{"title":"Add Product","parent":"ECommerce", "child":"Add Product"}}
    return render_template("applications/ecommerce/products/add-products.html",**context)


@main.route('/product_grid')
@login_required
def product_grid():
    context = { "breadcrumb":{"title":"Product Grid","parent":"Ecommerce", "child":"Product Grid"}}
    return render_template("applications/ecommerce/products/product-grid.html",**context)


@main.route('/list_products')
@login_required
def list_products():
    context = { "breadcrumb":{"title":"Product List","parent":"Ecommerce", "child":"Product List"}}
    return render_template("applications/ecommerce/products/list-products.html",**context)


@main.route('/product_details')
@login_required
def product_details():
    context = { "breadcrumb":{"title":"Product Details","parent":"Ecommerce", "child":"Product Details"}}
    return render_template("applications/ecommerce/products/product-details.html",**context)

@main.route('/category')
@login_required
def category():
    context = { "breadcrumb":{"title":"Category","parent":"Ecommerce", "child":"Category"}}
    return render_template("applications/ecommerce/category.html",**context)


@main.route('/seller_list')
@login_required
def seller_list():
    context = { "breadcrumb":{"title":"Seller List","parent":"Ecommerce", "child":"Seller List"}}
    return render_template("applications/ecommerce/seller/seller-list.html",**context)


@main.route('/seller_details')
@login_required
def seller_details():
    context = { "breadcrumb":{"title":"Seller Details","parent":"Ecommerce", "child":"Seller Details"}}
    return render_template("applications/ecommerce/seller/seller-details.html",**context)
           
@main.route('/order_history')
@login_required
def order_history():
    context = { "breadcrumb":{"title":"Order History","parent":"Ecommerce", "child":"Order History"}}
    return render_template("applications/ecommerce/orders/order-history.html",**context)
           
    
@main.route('/order_details')
@login_required
def order_details():
    context = { "breadcrumb":{"title":"Order Details","parent":"Ecommerce", "child":"Order Details"}}
    return render_template("applications/ecommerce/orders/order-details.html",**context)
       
           
@main.route('/invoice_1')
@login_required
def invoice_1():
    return render_template("applications/ecommerce/invoice-1.html")

@main.route('/invoice_2')
@login_required
def invoice_2():
    return render_template("applications/ecommerce/invoice-2.html")

@main.route('/invoice_3')
@login_required
def invoice_3():
    return render_template("applications/ecommerce/invoice-3.html")

@main.route('/invoice_4')
@login_required
def invoice_4():
    return render_template("applications/ecommerce/invoice-4.html")

@main.route('/invoice_5')
@login_required
def invoice_5():
    return render_template("applications/ecommerce/invoice-5.html")

@main.route('/invoice_6')
@login_required
def invoice_6():
    context = { "breadcrumb":{"title":"Invoice","parent":"Ecommerce", "child":"Invoice"}}
    return render_template("applications/ecommerce/invoice-template.html",**context)

@main.route('/cart')
@login_required
def cart():
    context = { "breadcrumb":{"title":"Cart","parent":"Ecommerce", "child":"Cart"}}
    return render_template("applications/ecommerce/cart.html",**context)
      
@main.route('/list_wish')
@login_required
def list_wish():
    context = { "breadcrumb":{"title":"Wishlist","parent":"Ecommerce", "child":"Wishlist"}}
    return render_template("applications/ecommerce/list-wish.html",**context)
     
@main.route('/checkout')
@login_required
def checkout():
    context = { "breadcrumb":{"title":"Checkout","parent":"Ecommerce", "child":"Checkout"}}
    return render_template("applications/ecommerce/checkout.html",**context)


#------------------------ Letter-Box
@main.route('/mail_box')
@login_required
def mail_box():
    context = { "breadcrumb":{"title":"Mail Box","parent":"Email", "child":"Mail Box"}}
    return render_template("applications/mail-box/mail-box.html",**context)


#--------------------------------chat
@main.route('/private_chat')
@login_required
def private_chat():
    context = { "breadcrumb":{"title":"Private Chat","parent":"Chat", "child":"Private Chat"}}
    return render_template("applications/chat/private-chat.html",**context)
     
@main.route('/group_chat')
@login_required
def group_chat():
    context = { "breadcrumb":{"title":"Group Chat","parent":"Chat", "child":"Group Chat"}}
    return render_template("applications/chat/group-chat.html",**context)



#---------------------------------user
@main.route('/user_profile')
@login_required
def user_profile():
    context = { "breadcrumb":{"title":"User Profile","parent":"Users", "child":"User Profile"}}
    return render_template("applications/users/user-profile.html",**context)
    
@main.route('/edit_profile')
@login_required
def edit_profile():
    context = { "breadcrumb":{"title":"User Edit","parent":"Users", "child":"User Edit"}}
    return render_template("applications/users/edit-profile.html",**context)
       
@main.route('/user_cards')
@login_required
def user_cards():
    context = { "breadcrumb":{"title":"User Cards","parent":"Users", "child":"User Cards"}}
    return render_template("applications/users/user-cards.html",**context)



#------------------------bookmark
@main.route('/bookmark')
@login_required
def bookmark():
    context = { "breadcrumb":{"title":"Bookmarks","parent":"Apps", "child":"Bookmarks"}}
    return render_template("applications/bookmark/bookmark.html",**context)


#------------------------contacts
@main.route('/contacts')
@login_required
def contacts():
    context = { "breadcrumb":{"title":"Contacts","parent":"Apps", "child":"Contacts"}}
    return render_template("applications/contacts/contacts.html",**context)


#------------------------task
@main.route('/task')
@login_required
def task():
    context = { "breadcrumb":{"title":"Tasks","parent":"Apps", "child":"Tasks"}}
    return render_template("applications/task/task.html",**context)
    

#------------------------calendar
@main.route('/calendar_basic')
@login_required
def calendar_basic():
    context = { "breadcrumb":{"title":"Calender Basic","parent":"Apps", "child":"Calender Basic"}}
    return render_template("applications/calendar/calendar-basic.html",**context)
    

#------------------------social-app
@main.route('/app_social')
@login_required
def app_social():
    context = { "breadcrumb":{"title":"Social App","parent":"Apps", "child":"Social App"}}
    return render_template("applications/social-app/social-app.html",**context)


#------------------------to-do
@main.route('/to_do')
@login_required
def to_do():
    context = { "breadcrumb":{"title":"To-Do","parent":"Apps", "child":"To-Do"}}
    return render_template("applications/to-do/to-do.html",**context)
    

#------------------------search
@main.route('/search')
@login_required
def search():
    context = { "breadcrumb":{"title":"Search Result","parent":"Search Pages", "child":"Search Result"}}
    return render_template("applications/search/search.html",**context)



#--------------------------------Forms & Table-----------------------------------------------
#--------------------------------Forms------------------------------------
#------------------------form-controls


@main.route('/form_validation')
@login_required
def form_validation():
    context = { "breadcrumb":{"title":"Validation Forms","parent":"Form Controls", "child":"Validation Forms"}}
    return render_template("forms-table/forms/form-controls/form-validation.html", **context)


@main.route('/base_input')
@login_required
def base_input():
    context = { "breadcrumb":{"title":"Base Inputs","parent":"Form Controls", "child":"Base Inputs"}}
    return render_template("forms-table/forms/form-controls/base-input.html", **context)    


@main.route('/radio_checkbox_control')
@login_required
def radio_checkbox_control():
    context = { "breadcrumb":{"title":"Checkbox & Radio","parent":"Form Controls", "child":"Checkbox & Radio"}}
    return render_template("forms-table/forms/form-controls/radio-checkbox-control.html", **context)

    
@main.route('/input_group')
@login_required
def input_group():
    context = { "breadcrumb":{"title":"Input Groups","parent":"Form Controls", "child":"Input Groups"}}
    return render_template("forms-table/forms/form-controls/input-group.html", **context)


@main.route('/input_mask')
@login_required
def input_mask():
    context = { "breadcrumb":{"title":"Input Mask","parent":"Form Controls", "child":"Input Mask"}}
    return render_template("forms-table/forms/form-controls/input-mask.html", **context)

    
@main.route('/megaoptions')
@login_required
def megaoptions():
    context = { "breadcrumb":{"title":"Mega Options","parent":"Form Controls", "child":"Mega Options"}}
    return render_template("forms-table/forms/form-controls/megaoptions.html", **context)    




#---------------------------form widgets

@main.route('/datepicker')
@login_required
def datepicker():
    context = { "breadcrumb":{"title":"Datepicker","parent":"Form Widgets", "child":"Datepicker"}}
    return render_template("forms-table/forms/form-widgets/datepicker.html", **context)


@main.route('/touchspin')    
@login_required
def touchspin():
    context = { "breadcrumb":{"title":"Touchspin","parent":"Form Widgets", "child":"Touchspin"}}
    return render_template('forms-table/forms/form-widgets/touchspin.html', **context)


@main.route('/select2')
@login_required
def select2():
    context = { "breadcrumb":{"title":"Select2","parent":"Form Widgets", "child":"Select2"}}
    return render_template('forms-table/forms/form-widgets/select2.html', **context)


@main.route('/switch')      
@login_required
def switch():
    context = { "breadcrumb":{"title":"Switch","parent":"Form Widgets", "child":"Switch"}}
    return render_template('forms-table/forms/form-widgets/switch.html', **context)
      

@main.route('/typeahead')      
@login_required
def typeahead():
    context = { "breadcrumb":{"title":"Typeahead","parent":"Form Widgets", "child":"Typeahead"}}
    return render_template('forms-table/forms/form-widgets/typeahead.html', **context)
      

@main.route('/clipboard')    
@login_required
def clipboard():
    context = { "breadcrumb":{"title":"Clipboard","parent":"Form Widgets", "child":"Clipboard"}}
    return render_template('forms-table/forms/form-widgets/clipboard.html', **context)
     
     
#-----------------------form layout

@main.route('/form_wizard_one')
@login_required
def form_wizard_one():
    context = { "breadcrumb":{"title":"Form Wizard 1","parent":"Form Layout", "child":"Form Wizard 1"}}
    return render_template('forms-table/forms/form-layout/form-wizard.html', **context) 


@main.route('/form_wizard_two')
@login_required
def form_wizard_two():
    context = { "breadcrumb":{"title":"Form Wizard 2","parent":"Form Layout", "child":"Form Wizard 2"}}
    return render_template('forms-table/forms/form-layout/form-wizard-two.html', **context) 


@main.route('/two_factor')
@login_required
def two_factor():
    context = { "breadcrumb":{"title":"Two Factor","parent":"Form Layout", "child":"Two Factor"}}
    return render_template('forms-table/forms/form-layout/two-factor.html', **context)



#----------------------------------------------------Table------------------------------------------
#------------------------bootstrap table

@main.route('/basic_table')
@login_required
def basic_table():
    context = { "breadcrumb":{"title":"Bootstrap Basic Tables","parent":"Bootstrap Tables", "child":"Bootstrap Basic Tables "}}
    return render_template('forms-table/table/bootstrap-table/bootstrap-basic-table.html', **context)
    

@main.route('/table_components')
@login_required
def table_components():
    context = { "breadcrumb":{"title":"Table Components","parent":"Bootstrap Tables", "child":"Table Components"}}
    return render_template('forms-table/table/bootstrap-table/table-components.html', **context)


#------------------------data table

@main.route('/datatable_basic_init')
@login_required
def datatable_basic_init():
    context = { "breadcrumb":{"title":"Basic DataTables","parent":"Data Tables", "child":"Basic DataTables"}}
    return render_template('forms-table/table/data-table/datatable-basic-init.html', **context)
    

@main.route('/datatable_advance')
@login_required
def datatable_advance():
    context = { "breadcrumb":{"title":"Advance Init","parent":"Data Tables", "child":"Advance Init"}}
    return render_template('forms-table/table/data-table/datatable-advance.html', **context)
    

@main.route('/datatable_API')
@login_required
def datatable_API():
    context = { "breadcrumb":{"title":"API DataTables","parent":"Data Tables", "child":"API DataTables"}}
    return render_template('forms-table/table/data-table/datatable-API.html', **context)
    

@main.route('/datatable_data_source')
@login_required
def datatable_data_source():
    context = { "breadcrumb":{"title":"DATA Source DataTables","parent":"Data Tables", "child":"DATA Source DataTables"}}
    return render_template('forms-table/table/data-table/datatable-data-source.html', **context)


#-------------------------------EX.data-table

@main.route('/ext_autofill')
@login_required
def ext_autofill():
    context = { "breadcrumb":{"title":"Autofill Datatables","parent":"Extension Data Tables", "child":"Autofill Datatables"}}
    return render_template('forms-table/table/Ex-data-table/datatable-ext-autofill.html', **context)


#--------------------------------jsgrid_table

@main.route('/jsgrid_table')
@login_required
def jsgrid_table():
    context = { "breadcrumb":{"title":"JS Grid Tables","parent":"Tables", "child":"JS Grid Tables"}}
    return render_template('forms-table/table/js-grid-table/jsgrid-table.html', **context)  




#------------------Components------UI Components-----Elements ----------->

#-----------------------------Ui kits

@main.route('/typography')
@login_required
def typography():
    context = { "breadcrumb":{"title":"Typography","parent":"Ui Kits", "child":"Typography"}}
    return render_template('components/ui-kits/typography.html', **context) 


@main.route('/avatars')
@login_required
def avatars():
    context = { "breadcrumb":{"title":"Avatars","parent":"Ui Kits", "child":"Avatars"}}
    return render_template('components/ui-kits/avatars.html', **context) 


@main.route('/divider')
@login_required
def divider():
    context = { "breadcrumb":{"title":"Divider","parent":"Ui Kits", "child":"Divider"}}
    return render_template('components/ui-kits/divider.html', **context) 


@main.route('/helper_classes')
@login_required
def helper_classes():
    context = { "breadcrumb":{"title":"Helper Classes","parent":"Ui Kits", "child":"Helper Classes"}}
    return render_template('components/ui-kits/helper-classes.html', **context) 


@main.route('/grid')
@login_required
def grid():
    context = { "breadcrumb":{"title":"Grid","parent":"Ui Kits", "child":"Grid"}}
    return render_template('components/ui-kits/grid.html', **context) 

     
@main.route('/tagpills')      
@login_required
def tagpills():
    context = { "breadcrumb":{"title":"Tag & Pills","parent":"Ui Kits", "child":"Tag & Pills"}}
    return render_template('components/ui-kits/tag-pills.html', **context) 


@main.route('/progressbar')
@login_required
def progressbar():
    context = { "breadcrumb":{"title":"Progress","parent":"Ui Kits", "child":"Progress"}}
    return render_template('components/ui-kits/progress-bar.html', **context) 


@main.route('/modal')
@login_required
def modal():
    context = { "breadcrumb":{"title":"Modal","parent":"Ui Kits", "child":"Modal"}}
    return render_template('components/ui-kits/modal.html', **context)   


@main.route('/alert')
@login_required
def alert():
    context = { "breadcrumb":{"title":"Alerts","parent":"Ui Kits", "child":"Alerts"}}
    return render_template('components/ui-kits/alert.html', **context) 


@main.route('/popover')   
@login_required
def popover():
    context = { "breadcrumb":{"title":"Popover","parent":"Ui Kits", "child":"Popover"}}
    return render_template('components/ui-kits/popover.html', **context)  


@main.route('/placeholder')   
@login_required
def placeholder():
    context = { "breadcrumb":{"title":"Placeholders","parent":"Ui Kits", "child":"Placeholders"}}
    return render_template('components/ui-kits/placeholders.html', **context)  


@main.route('/tooltip')
@login_required
def tooltip():
    context = { "breadcrumb":{"title":"Tooltip","parent":"Ui Kits", "child":"Tooltip"}}
    return render_template('components/ui-kits/tooltip.html', **context) 


@main.route('/dropdown')
@login_required
def dropdown():
    context = { "breadcrumb":{"title":"Dropdowns","parent":"Ui Kits", "child":"Dropdowns"}}
    return render_template('components/ui-kits/dropdown.html', **context)    


@main.route('/accordion')
@login_required
def accordion():
    context = { "breadcrumb":{"title":"Accordions","parent":"Ui Kits", "child":"Accordions"}}
    return render_template('components/ui-kits/according.html', **context)     

     
@main.route('/bootstraptab')
@login_required
def bootstraptab():
    context = { "breadcrumb":{"title":"Bootstrap Tabs","parent":"Ui Kits", "child":"Bootstrap Tabs"}}
    return render_template('components/ui-kits/tab-bootstrap.html', **context)     
    

@main.route('/offcanvas')
@login_required
def offcanvas():
    context = {"breadcrumb":{"title":"Offcanvas","parent":"Ui Kits", "child":"Offcanvas"}}
    return render_template('components/ui-kits/offcanvas.html', **context)  


@main.route('/navigate_links')
@login_required
def navigate_links():
    context = {"breadcrumb":{"title":"Navigate Links","parent":"Ui Kits", "child":"Navigate Links"}}
    return render_template('components/ui-kits/navigate-links.html', **context)  


@main.route('/lists')
@login_required
def lists():
    context = {"breadcrumb":{"title":"Lists","parent":"Ui Kits", "child":"Lists"}}
    return render_template('components/ui-kits/list.html', **context)  


#-------------------------------Bonus Ui

@main.route('/scrollable')
@login_required
def scrollable():
    context = {"breadcrumb":{"title":"Scrollable","parent":"Bonus Ui", "child":"Scrollable"}}
    return render_template('components/bonus-ui/scrollable.html', **context)
            
            
@main.route('/tree')
@login_required
def tree():
    context = {"breadcrumb":{"title":"Tree View","parent":"Bonus Ui", "child":"Tree View"}}
    return render_template('components/bonus-ui/tree.html', **context)


@main.route('/toasts')           
@login_required
def toasts():
    context = {"breadcrumb":{"title":"Toasts","parent":"Bonus Ui", "child":"Toasts"}}
    return render_template('components/bonus-ui/toasts.html', **context)      

  
@main.route('/blockUi')    
@login_required
def blockUi():
    context = {"breadcrumb":{"title":"Block Ui","parent":"Bonus Ui", "child":"Block Ui"}}
    return render_template('components/bonus-ui/block-ui.html', **context)


@main.route('/rating')    
@login_required
def rating():
    context = {"breadcrumb":{"title":"Rating","parent":"Bonus Ui", "child":"Rating"}}
    return render_template('components/bonus-ui/rating.html', **context)
               
               
@main.route('/dropzone')
@login_required
def dropzone():
    context = {"breadcrumb":{"title":"Dropzone","parent":"Bonus Ui", "child":"Dropzone"}}
    return render_template('components/bonus-ui/dropzone.html', **context)    
    
    
@main.route('/tour')
@login_required
def tour():
    context = {"breadcrumb":{"title":"Tour","parent":"Bonus Ui", "child":"Tour"}}
    return render_template('components/bonus-ui/tour.html', **context)        
    
    
@main.route('/sweetalert2')
@login_required
def sweetalert2():
    context = {"breadcrumb":{"title":"Sweet Alert","parent":"Bonus Ui", "child":"Sweet Alert"}}
    return render_template('components/bonus-ui/sweet-alert2.html', **context)    
    
    
@main.route('/animatedmodal')
@login_required
def animatedmodal():
    context = {"breadcrumb":{"title":"Animated Modal","parent":"Bonus Ui", "child":"Animated Modal"}}
    return render_template('components/bonus-ui/modal-animated.html', **context)     


@main.route('/owlcarousel')
@login_required
def owlcarousel():
    context = {"breadcrumb":{"title":"Owl Carousel","parent":"Bonus Ui", "child":"Owl Carousel"}}
    return render_template('components/bonus-ui/owl-carousel.html', **context)     


@main.route('/ribbons')
@login_required
def ribbons():
    context = {"breadcrumb":{"title":"Ribbons","parent":"Bonus Ui", "child":"Ribbons"}}
    return render_template('components/bonus-ui/ribbons.html', **context) 



@main.route('/pagination')
@login_required
def pagination():
    context = {"breadcrumb":{"title":"Paginations","parent":"Bonus Ui", "child":"Paginations"}}
    return render_template('components/bonus-ui/pagination.html', **context)  


@main.route('/scrollspy')
@login_required
def scrollspy():
    context = {"breadcrumb":{"title":"ScrollSpy","parent":"Bonus Ui", "child":"ScrollSpy"}}
    return render_template('components/bonus-ui/scrollspy.html', **context)  


@main.route('/breadcrumb')
@login_required
def breadcrumb():
    context = {"breadcrumb":{"title":"Breadcrumb","parent":"Bonus Ui", "child":"Breadcrumb"}}
    return render_template('components/bonus-ui/breadcrumb.html', **context)  

    
@main.route('/rangeslider')
@login_required
def rangeslider():
    context = {"breadcrumb":{"title":"Range Slider","parent":"Bonus Ui", "child":"Range Slider"}}
    return render_template('components/bonus-ui/range-slider.html', **context)  

   
@main.route('/ratios')
@login_required
def ratios():
    context = {"breadcrumb":{"title":"Ratios","parent":"Bonus Ui", "child":"Ratios"}}
    return render_template('components/bonus-ui/ratios.html', **context)     
    
    
@main.route('/imagecropper')
@login_required
def imagecropper():
    context = {"breadcrumb":{"title":"Image Cropper","parent":"Bonus Ui", "child":"Image Cropper"}}
    return render_template('components/bonus-ui/image-cropper.html', **context)      
    

@main.route('/basiccard')
@login_required
def basiccard():
    context = {"breadcrumb":{"title":"Basic Card","parent":"Bonus Ui", "child":"Basic Card"}}
    return render_template('components/bonus-ui/basic-card.html', **context)
                    
                    
@main.route('/creativecard')
@login_required
def creativecard():
    context = {"breadcrumb":{"title":"Creative Card","parent":"Bonus Ui", "child":"Creative Card"}}
    return render_template('components/bonus-ui/creative-card.html', **context)  
       

@main.route('/draggablecard')
@login_required
def draggablecard():
    context = {"breadcrumb":{"title":"Draggable Card","parent":"Bonus Ui", "child":"Draggable Card"}}
    return render_template('components/bonus-ui/draggable-card.html', **context)       
    
    
@main.route('/timeline')    
@login_required
def timeline():
    context = {"breadcrumb":{"title":"Timeline","parent":"Bonus Ui", "child":"Timeline"}}
    return render_template('components/bonus-ui/timeline-v-1.html', **context)   



#---------------------------------Animation


@main.route('/animate')
@login_required
def animate():
    context = {"breadcrumb":{"title":"Animate","parent":"Animation", "child":"Animate"}}
    return render_template('components/animation/animate.html', **context)
            
            
@main.route('/scrollreval')
@login_required
def scrollreval():
    context = {"breadcrumb":{"title":"Scroll Reveal","parent":"Animation", "child":"Scroll Reveal"}}
    return render_template('components/animation/scroll-reval.html', **context)        
    

@main.route('/AOS')
@login_required
def AOS():
    context = {"breadcrumb":{"title":"AOS Animation","parent":"Animation", "child":"AOS Animation"}}
    return render_template('components/animation/AOS.html', **context)
            

@main.route('/tilt')
@login_required
def tilt():
    context = {"breadcrumb":{"title":"Tilt Animation","parent":"Animation", "child":"Tilt Animation"}}
    return render_template('components/animation/tilt.html', **context)        
    
    
@main.route('/wow')
@login_required
def wow():
    context = {"breadcrumb":{"title":"Wow Animation","parent":"Animation", "child":"Wow Animation"}}
    return render_template('components/animation/wow.html', **context)   


@main.route('/flashicon')
@login_required
def flashicon():
    context = {"breadcrumb":{"title":"Flash Icons","parent":"Animation", "child":"Flash Icons"}}
    return render_template('components/animation/flash-icon.html', **context) 



#--------------------------Icons

@main.route('/flagicon')
@login_required
def flagicon():
    context = {"breadcrumb":{"title":"Flag Icons","parent":"Icons", "child":"Flag Icons"}}
    return render_template('components/icons/flag-icon.html', **context) 


@main.route('/fontawesome')
@login_required
def fontawesome():
    context = {"breadcrumb":{"title":"Font Awesome Icon","parent":"Icons", "child":"Font Awesome Icon"}}
    return render_template('components/icons/font-awesome.html', **context) 
    

@main.route('/icoicon')
@login_required
def icoicon():
    context = {"breadcrumb":{"title":"ICO Icon","parent":"Icons", "child":"ICO Icon"}}
    return render_template('components/icons/ico-icon.html', **context) 

 
@main.route('/themify')
@login_required
def themify():
    context = {"breadcrumb":{"title":"Themify Icon","parent":"Icons", "child":"Themify Icon"}}
    return render_template('components/icons/themify-icon.html', **context)  


@main.route('/feather')    
@login_required
def feather():
    context = {"breadcrumb":{"title":"Feather Icons","parent":"Icons", "child":"Feather Icons"}}
    return render_template('components/icons/feather-icon.html', **context) 
    
    
@main.route('/whether')
@login_required
def whether():
    context = {"breadcrumb":{"title":"Whether Icon","parent":"Icons", "child":"Whether Icon"}}
    return render_template('components/icons/whether-icon.html', **context)  


#--------------------------------Buttons

@main.route('/buttons')
@login_required
def buttons():
    context = {"breadcrumb":{"title":"Buttons","parent":"Buttons", "child":"Buttons"}}
    return render_template('components/buttons/buttons.html', **context)        



#-------------------------------Charts

@main.route('/apex')
@login_required
def apex():
    context = {"breadcrumb":{"title":"Apex Chart","parent":"Charts", "child":"Apex Chart"}}
    return render_template('components/charts/chart-apex.html', **context)    
    
    
@main.route('/google')         
@login_required
def google():
    context = {"breadcrumb":{"title":"Google Chart","parent":"Charts", "child":"Google Chart"}}
    return render_template('components/charts/chart-google.html', **context)


@main.route('/sparkline')         
@login_required
def sparkline():
    context = {"breadcrumb":{"title":"Sparkline Chart","parent":"Charts", "child":"Sparkline Chart"}}
    return render_template('components/charts/chart-sparkline.html', **context)      


@main.route('/flot')             
@login_required
def flot():
    context = {"breadcrumb":{"title":"Flot Chart","parent":"Charts", "child":"Flot Chart"}}
    return render_template('components/charts/chart-flot.html', **context)   
    

@main.route('/knob')
@login_required
def knob():
    context = {"breadcrumb":{"title":"Knob Chart","parent":"Charts", "child":"Knob Chart"}}
    return render_template('components/charts/chart-knob.html', **context)     
       
       
@main.route('/morris')         
@login_required
def morris():
    context = {"breadcrumb":{"title":"Morris Chart","parent":"Charts", "child":"Morris Chart"}}
    return render_template('components/charts/chart-morris.html', **context)


@main.route('/chartjs')      
@login_required
def chartjs():
    context = {"breadcrumb":{"title":"ChartJS Chart","parent":"Charts", "child":"ChartJS Chart"}}
    return render_template('components/charts/chartjs.html', **context)     
    
    
@main.route('/chartist')
@login_required
def chartist():
    context = {"breadcrumb":{"title":"Chartist Chart","parent":"Charts", "child":"Chartist Chart"}}
    return render_template('components/charts/chartist.html', **context)   


@main.route('/peity')
@login_required
def peity():
    context = {"breadcrumb":{"title":"Peity Chart","parent":"Charts", "child":"Peity Chart"}}
    return render_template('components/charts/chart-peity.html', **context)  



#------------------------------------------Pages-------------------------------------

#-------------------------sample-page

@main.route('/sample_page')
@login_required
def sample_page():
    context = {"breadcrumb":{"title":"Sample Page","parent":"Pages", "child":"Sample Page"}}    
    return render_template('pages/sample-page/sample-page.html', **context)
    
#--------------------------internationalization

@main.route('/internationalization')
@login_required
def internationalization():
    context = {"breadcrumb":{"title":"Internationalization","parent":"Pages", "child":"Internationalization"}}
    return render_template('pages/internationalization/internationalization.html', **context)




# ------------------------------error page

@main.route('/error_400')
@login_required
def error_400():
    return render_template('pages/error-pages/error-400.html')


@main.route('/error_401')
@login_required
def error_401():
    return render_template('pages/error-pages/error-401.html')
    

@main.route('/error_403')
@login_required
def error_403():
    return render_template('pages/error-pages/error-403.html')


@main.route('/error_404')
@login_required
def error_404():
    return render_template('pages/error-pages/error-404.html')
    

@main.route('/error_500')
@login_required
def error_500():
    return render_template('pages/error-pages/error-500.html')
    

@main.route('/error_503')
@login_required
def error_503():
    return render_template('pages/error-pages/error-503.html')
    

#----------------------------------Authentication



@main.route('/login_simple')
@login_required
def login_simple():
    return render_template('pages/authentication/login.html')


@main.route('/login_one')
@login_required
def login_one():
    return render_template('pages/authentication/login_one.html')
    

@main.route('/login_two')
@login_required
def login_two():
    return render_template('pages/authentication/login_two.html')


@main.route('/login_bs_validation')
@login_required
def login_bs_validation():
    return render_template('pages/authentication/login-bs-validation.html')


@main.route('/login_tt_validation')
@login_required
def login_tt_validation():
    return render_template('pages/authentication/login-bs-tt-validation.html')
    

@main.route('/login_validation')
@login_required
def login_validation():
    return render_template('pages/authentication/login-sa-validation.html')
    

@main.route('/sign_up')
@login_required
def sign_up():
    return render_template('pages/authentication/sign-up.html')  


@main.route('/sign_one')
@login_required
def sign_one():
    return render_template('pages/authentication/sign-up-one.html')
    

@main.route('/sign_two')
@login_required
def sign_two():
    return render_template('pages/authentication/sign-up-two.html')


@main.route('/sign_wizard')
@login_required
def sign_wizard():
    return render_template('pages/authentication/sign-up-wizard.html')    


@main.route('/unlock')
@login_required
def unlock():
    return render_template('pages/authentication/unlock.html')
    

@main.route('/forget_password')
def forget_password():
    return render_template('pages/authentication/forget-password.html')
    

@main.route('/reset_password')
@login_required
def reset_password():
    return render_template('pages/authentication/reset-password.html')


@main.route('/maintenance')
@login_required
def maintenance():
    return render_template('pages/authentication/maintenance.html')



#---------------------------------------comingsoon

@main.route('/comingsoon')
@login_required
def comingsoon():
    return render_template('pages/comingsoon/comingsoon.html')
    

@main.route('/comingsoon_video')
@login_required
def comingsoon_video():
    return render_template('pages/comingsoon/comingsoon-bg-video.html')


@main.route('/comingsoon_img')
@login_required
def comingsoon_img():
    return render_template('pages/comingsoon/comingsoon-bg-img.html' )
    

#----------------------------------Email-Template

@main.route('/basic_temp')
@login_required
def basic_temp():
    return render_template('pages/email-templates/basic-template.html')
    

@main.route('/email_header')
@login_required
def email_header():
    return render_template('pages/email-templates/email-header.html')
    

@main.route('/template_email')
@login_required
def template_email():
    return render_template('pages/email-templates/template-email.html')
    

@main.route('/template_email_2')
@login_required
def template_email_2():
    return render_template('pages/email-templates/template-email-2.html')


@main.route('/ecommerce_temp')
@login_required
def ecommerce_temp():
    return render_template('pages/email-templates/ecommerce-templates.html')
    

@main.route('/email_order')
@login_required
def email_order():
    return render_template('pages/email-templates/email-order-success.html')   

  
    
@main.route('/pricing')
@login_required
def pricing():
    context = { "breadcrumb":{"title":"Pricing","parent":"Pages", "child":"Pricing"}}
    return render_template("pages/pricing/pricing.html", **context)


#--------------------------------------faq

@main.route('/FAQ')
@login_required
def FAQ():
    context = {"breadcrumb":{"title":"FAQ","parent":"Pages", "child":"FAQ"}}    
    return render_template('pages/FAQ/faq.html', **context)



#------------------------------------------Miscellaneous----------------- -------------------------

#--------------------------------------gallery

@main.route('/gallery_grid')
@login_required
def gallery_grid():
    context = {"breadcrumb":{"title":"Gallery","parent":"Gallery", "child":"Gallery"}}    
    return render_template('miscellaneous/gallery/gallery.html', **context)
    


@main.route('/gallery_description')
@login_required
def gallery_description():
    context = {"breadcrumb":{"title":"Gallery Grid With Description","parent":"Gallery", "child":"Gallery Grid With Description"}}    
    return render_template('miscellaneous/gallery/gallery-with-description.html', **context)
    


@main.route('/masonry_gallery')
@login_required
def masonry_gallery():
    context = {"breadcrumb":{"title":"Masonry Gallery","parent":"Gallery", "child":"Masonry Gallery"}}    
    return render_template('miscellaneous/gallery/gallery-masonry.html', **context)
    


@main.route('/masonry_disc')
@login_required
def masonry_disc():
    context = {"breadcrumb":{"title":"Masonry Gallery With Description","parent":"Gallery", "child":"Masonry Gallery With Description"}}    
    return render_template('miscellaneous/gallery/masonry-gallery-with-disc.html', **context)
    


@main.route('/hover')
@login_required
def hover():
    context = {"breadcrumb":{"title":"Image Hover Effects","parent":"Gallery", "child":"Image Hover Effects"}}    
    return render_template('miscellaneous/gallery/gallery-hover.html', **context)
    
#------------------------------------Blog

@main.route('/blog_details')
@login_required
def blog_details():  
    context = {"breadcrumb":{"title":"Blog Details","parent":"Blog", "child":"Blog Details"}}    
    return render_template('miscellaneous/blog/blog.html', **context)


@main.route('/blog_single')
@login_required
def blog_single():
    context = {"breadcrumb":{"title":"Blog Single","parent":"Blog", "child":"Blog Single"}}    
    return render_template('miscellaneous/blog/blog-single.html', **context)


@main.route('/add_post')
@login_required
def add_post():
    context = {"breadcrumb":{"title":"Add Post","parent":"Blog", "child":"Add Post"}}    
    return render_template('miscellaneous/blog/add-post.html', **context)
    

#---------------------------------job serach

@main.route('/job_cards')
@login_required
def job_cards():
    context = {"breadcrumb":{"title":"Cards View","parent":"Job search", "child":"Cards View"}}    
    return render_template('miscellaneous/job-search/job-cards-view.html', **context)
    

@main.route('/job_list')
@login_required
def job_list():
    context = {"breadcrumb":{"title":"List View","parent":"Job search", "child":"List View"}}    
    return render_template('miscellaneous/job-search/job-list-view.html', **context)
    

@main.route('/job_details')
@login_required
def job_details():
    context = {"breadcrumb":{"title":"Job Details","parent":"Job search", "child":"Job Details"}}    
    return render_template('miscellaneous/job-search/job-details.html', **context)
    

@main.route('/apply')
@login_required
def apply():
    context = {"breadcrumb":{"title":"Apply","parent":"Job search", "child":"Apply"}}    
    return render_template('miscellaneous/job-search/job-apply.html', **context)
    
#------------------------------------Learning

@main.route('/course_list')
@login_required
def course_list():
    context = {"breadcrumb":{"title":"Course List","parent":"Course", "child":"Course List"}}    
    return render_template('miscellaneous/courses/course-list-view.html', **context)
    

@main.route('/course_detailed')
@login_required
def course_detailed():
    context = {"breadcrumb":{"title":"Course Details","parent":"Course", "child":"Course Details"}}    
    return render_template('miscellaneous/courses/course-detailed.html', **context)
    

#----------------------------------------Maps
@main.route('/data_map')
@login_required
def data_map():
    context = {"breadcrumb":{"title":"Map JS","parent":"Maps", "child":"Map JS"}}    
    return render_template('miscellaneous/maps/map-js.html', **context)
    
   
@main.route('/vector_maps')
@login_required
def vector_maps():
    context = {"breadcrumb":{"title":"Vector Maps","parent":"Maps", "child":"Vector Maps"}}
    return render_template('miscellaneous/maps/vector-map.html', **context)
    

#------------------------------------Editors
   
@main.route('/quilleditor')
@login_required
def quilleditor():
    context = {"breadcrumb":{"title":"Quill Editor","parent":"Editors", "child":"Quill Editor"}}    
    return render_template('miscellaneous/editors/quilleditor.html', **context)
    

@main.route('/ckeditor')
@login_required
def ckeditor():
    context = {"breadcrumb":{"title":"Ck Editor","parent":"Editors", "child":"Ck Editor"}}    
    return render_template('miscellaneous/editors/ckeditor.html', **context)
    
    
@main.route('/ace_code')
@login_required
def ace_code():
    context = {"breadcrumb":{"title":"ACE Code Editor","parent":"Editors", "child":"ACE Code Editor"}}    
    return render_template('miscellaneous/editors/ace-code-editor.html', **context) 
    
    
#----------------------------knowledgebase
@main.route('/knowledgebase')
@login_required
def knowledgebase():
    context = {"breadcrumb":{"title":"Knowledgebase","parent":"Knowledgebase", "child":"Knowledgebase"}}    
    return render_template('miscellaneous/knowledgebase/knowledgebase.html', **context)
    
    
#-----------------------------support-ticket
@main.route('/support_ticket')    
@login_required
def support_ticket():
    context = { "breadcrumb":{"title":"Support Ticket","parent":"Support Ticket", "child":"Support Ticket"}}
    return render_template("miscellaneous/support-ticket/support-ticket.html", **context)




#---------------------------------------------------------------------------------------


@main.route('/to_do_view')
@login_required
def to_do_view():
    context={"breadcrumb":{"parent":"Apps","child":"To-Do"}}
    return render_template('applications/to-do/main-todo.html',**context)


@main.route('/to_do_database')
@login_required
def to_do_database():
     todos = Todo.query.all()
     allTasksComplete = True

     for todo in todos:
        if not todo.completed:
            allTasksComplete = False
            break

     context = { "allTasksComplete":allTasksComplete,"todos":todos, "breadcrumb":{"parent":"Todo", "child":"Todo with database"}}

     return render_template('applications/to-do/to-do.html',**context)
    

@main.route('/to_do_database',methods=['POST'])
def add_todo():
    description = request.form.get('description')
    if description != '':
        new_task = Todo(description=description)
        db.session.add(new_task)
        db.session.commit()

    return redirect('/to_do_database')

@main.route('/markAllTasksComplete')

def markAllComplete():
    todos = Todo.query.all()
    for todo in todos:
        update_todo = Todo.query.filter_by(id = todo.id).first()
        update_todo.completed = True
        db.session.commit()
    return redirect('/to_do_database')


@main.route('/toggleComplete/<int:id>')
def toggleComplete(id):
    todo = Todo.query.filter_by(id = id).first()
    todo.completed = not todo.completed
    db.session.commit()
    return redirect('/to_do_database')

@main.route('/deleteTask/<int:id>')
def deleteTask(id): 
    Todo.query.filter_by(id=id).delete()
    db.session.commit()
    return redirect('/to_do_database')
