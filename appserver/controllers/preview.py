import re, sys, logging, traceback, tempfile, os, json, datetime, time, math
import cherrypy
import splunk.appserver.mrsparkle as mrsparkle
import splunk.appserver.mrsparkle.controllers as controllers
from splunk.appserver.mrsparkle.lib.decorators import expose_page
from splunk.appserver.mrsparkle.lib.routes import route
from splunk.appserver.mrsparkle.lib import util
import splunk.util
import splunk.bundle as bundle
import splunk.search as se
import splunk.entity as entity
import splunk.rest as rest

logger = logging.getLogger('preview')

# stop analyzing after we have N good different parses
MAX_PARSE_BEFORE_GIVE_UP = 10   # if we have 10 different linebreaking/timestamps, stop deduping
MAX_POP_STANZAS = 1000             # keep 50 most popular stanzas
MAX_SECS_BEFORE_NO_DEDUP = 10   # if previewing any given sourcetype takes more than 10 seconds, stop trying to dedup sourcetypes
MAX_SECS_FOR_DEDUP = 60   # if previewing takes more than 10 seconds, stop trying to dedup sourcetypes
MAX_DATA_LEN = 1000             # work on up to 1k of text

class PreviewController(controllers.BaseController):
    '''/preview'''

    @route('/')
    @expose_page(must_login=True, methods=['GET', 'POST'])
    def index(self, **kwargs):

        try:
            
            cherrypy.response.headers['content-type'] = mrsparkle.MIME_HTML
            self._targs = { 'messages': {'error':[], 'warn':[], 'info':[] },
                            'events': [],
                            'stanzas': [],
                            'stanza': '',
                            'data': '',
                            'settings': ''
                            }

            sessionKey = kwargs['sessionKey'] = cherrypy.session['sessionKey']

            if not splunk.auth.ping(sessionKey=sessionKey):
                return self.redirect_to_url('/account/login', _qs=[ ('return_to', util.current_url_path())])

            namespace  = kwargs.get('namespace',None)
            username = cherrypy.session['user']['name']

            self._sessionKey = sessionKey
            self._mynamespace = namespace
            self._owner = username

            self.previewPage(**kwargs)
        except Exception, e:
            return self.outputError('Exception: %s.' % e)
        
        page = "preview"
        cherrypy.response.headers['content-type'] = mrsparkle.MIME_HTML
        return self.render_template('preview:/templates/preview/%s.html' % page, self._targs)

    def outputError(self, msg):
        self.addMsg('error', msg)
        return self.render_template('preview:/templates/preview/error.html', self._targs)

    def addMsg(self, level, text):
        #print "%s: %s" % (level, text)
        self._targs['messages'][level].append(str(text))
        if level == 'error':
            self.addMsg('warn', 'Stacktrace: %s' % traceback.format_exc())



    def previewPage(self, **kwargs):

        old_data = kwargs.get('old_data', None)
        old_stanza_name_count = kwargs.get('old_stanzas', None)

        stanza = kwargs.get('stanza', None)
        data     = kwargs.get('data', '').strip()[:MAX_DATA_LEN] # take a sample

        stanza_name_count = []
        events   = []
        stanzas = {}

        if len(data) == 0:
            self.addMsg('warn', 'Please copy and paste some data.')
        else:
            stanza = kwargs.get('stanza', None)
            stanzas = self.getStanzas()
            # IF THE USER DIDN'T CHANGE THE DATA SINCE THE LAST RUN,
            # USE THE CACHED LIST OF SOURCETYPES
            if old_data == data:
                if old_stanza_name_count:
                    stanza_name_count = json.loads(old_stanza_name_count)

            if len(stanza_name_count) == 0:


                stanzas = self.filterStanzas(stanzas, data)            

                self.keepPopular(stanzas)

                self.dedupStanzas(stanzas, data)
                items = stanzas.items()

                items.sort(key=lambda x: int(x[1]['count']), reverse=True)
                stanza_name_count = [(name, vals['count']) for name,vals in items]

            # if no stanza picked, pick the most popular (first)
            if stanza == '' or stanza == None or stanza not in stanzas.keys(): 
                stanza = stanza_name_count[0][0]
           
            #self.addMsg('info', 'Settings for %s: %s' % (stanza, stanzas.get(stanza, {})))
            try:
                events = self.getPreviewEvents(data, stanza, stanzas.get(stanza, {}))
            except Exception, e:
                logger.error('Preview App: Problem deduping %s: %s\n %s' % (name, e, traceback.format_exc()))
                self.addMsg('warn', 'Problem getting preview: %s' % e)
            

        self._targs['events'] = events
        self._targs['stanzas'] = stanza_name_count
        self._targs['stanza'] = stanza
        self._targs['data'] = data
        self._targs['settings'] = stanzas.get(stanza,{})

    def getStanzas(self):
        # get stanzas
        stanzas = bundle.getConf('preview_props', sessionKey=self._sessionKey, namespace=self._mynamespace, owner=self._owner)
        # convert to dict obj and not a conf obj tied to modifying conf system
        dictstanzas = {}
        for name in stanzas.keys():
            d = {}
            for a,v in stanzas[name].items():
                d[a] = v
            dictstanzas[name] = d
        return dictstanzas


    def OLDgetPreviewEvents(self, eventdata, stanza):
        ### !!! TEMP!  just return an event on each line
        if eventdata == None:
            return []
        return [event for event in eventdata.split('\n')]


##    def fixStrptime(self, s):
##        best_replacements = [ 
##            (['%T'], '%H : %M : %S'),
##            (['%e'], '%d'),
##            (['%n'], '%t'),
##            (['%P'], '%p'),
##            (['%D'], '%m / %d / %y'),
##            (['%6N', '%3N', '%N', '%6Q', '%3Q', '%Q', '%q'], '%f'),
##            (['%r'], '%I : %M : %S %p'),
##            (['%t', '%n'], ' '), # these suck.  no python directive for whitespace
##            (['%z', '%::z', '%:::z'], '%Z')
##            ]
##        for patterns, replacement in best_replacements:
##            for pattern in patterns:
##                s = s.replace(pattern, replacement)
##        return s

    def keepPopular(self, stanzas):
        # remove any stanzas that aren't the top N most popular
        popular_names = self.popularStanzaNames(stanzas)[:MAX_POP_STANZAS]
        for name in stanzas.keys():
            if name not in popular_names:
                del stanzas[name]

    def popularStanzaNames(self, stanzas):
        items = stanzas.items()
        items.sort(key=lambda x: int(x[1]['count']), reverse=True)
        names = [name for name,vals in items]
        return names


    def filterStanzas(self, stanzas, data):
        doomed = set()

        for stanzaname in stanzas.keys():
            try:
                values = stanzas[stanzaname]
                bad = False
                for attr, value in values.items():
                    # if attr is a regex and it doesn't match the data, mark it as bad
                    if attr in ['TIME_PREFIX', 'LINE_BREAKER', 'BREAK_ONLY_BEFORE', 'MUST_BREAK_AFTER', 'MUST_NOT_BREAK_BEFORE', 'MUST_NOT_BREAK_AFTER'] and len(value)>3:
                        if not re.search("(?ms)" + value, data) and not value.startswith("goobly"):
                            bad = True
                            #print "%s DOOMED BECAUSE OF %s (%s) against (%s)" % (stanzaname, attr, value, data[:100])
##                    # if we have a strptime
##                    if attr == 'TIME_FORMAT':
##                        # skip to prefix
##                        if 'TIME_PREFIX' in values:
##                            prefix = '(?ms)' + values['TIME_PREFIX'] # make it multiline
##                            m = re.search(prefix, data)
##                            if not m:
##                                #print "BAD TIME_PREFIX: (%s)(%s)" % (prefix, data[:100])
##                                break
##                            text = data[m.end():]
##                        else:
##                            text = data
##                        try:
##                            value = self.fixStrptime(value)
##                            #time.strptime(text, value)
##                            datetime.datetime.strptime(text, value)
##                            #print "GOOD STRPTIME:", value, text[:100]
##                            # bad = False
##                        except Exception, e:
##                            # if we got a valid strptime parse but it didn't match, mark as bad
##                            if "does not match" in str(e):
##                                bad = True
##                            # self.addMsg('warn', '%s: %s. BAD STRPTIME ' % (e, stanzaname))
##                            #print "BAD STRPTIME:", value, text[:100]
##                            break
                if bad:
                    doomed.add(stanzaname)
                    #print "BAD!", stanzaname
                #else:
                    #print "GOOD!", stanzaname
            except Exception, e:
                self.addMsg('warn', 'Problem filtering %s: %s. %s' % (stanzaname, e, values))
                doomed.add(stanzaname)
        #print "DOOMED:", len(doomed), "STANZAS:", len(stanzas)
        for d in doomed:
            if d in stanzas:
                del stanzas[d]
            else:
                print "CAN'T FIND ", d
            # TEMP
            #stanzas['ZZZZZZZ' + d] = {}
        return stanzas


    def dedupStanzas(self, stanzas, eventdata):

        # get names of stanzas and sort from most popular to least
        items = stanzas.items()
        items.sort(key=lambda x: int(x[1]['count']), reverse=True)
        names = [name for name,vals in items]

        start = time.time()
        seenParses = set()
        hadErrors = None
        # for each stanza name
        for name in names:
            try:
                # stop analyzing after we've spent too much time, or we have N good different parses
                if time.time() > start + MAX_SECS_FOR_DEDUP or len(seenParses) > MAX_PARSE_BEFORE_GIVE_UP:
                    stanzas[name]['count'] = -1
                    print "GIViNG UP:", (time.time() - (start + MAX_SECS_FOR_DEDUP)), len(seenParses)
                    continue
                
                now = time.time()
                

                #print "EVENTS:", eventdata[:1000].replace("\n", "\\n")
                settings = stanzas.get(name, None)
                print "SETTINGS", name, settings


                if settings == None:
                    stanzas[name]['count'] = -1
                    print 'NO SETTINGS FOR:', settings
                    continue

                events = self.getPreviewEvents(eventdata, name, settings)
                #print "EVENT1: '%s'" % events[0]
                #if name == 'misc_text':
                #    sys.exit(-1)
                if time.time() - now > MAX_SECS_BEFORE_NO_DEDUP:
                    self.addMsg('warn', 'Previewing is taking too long to dedup stanzas.  Check system for performance problems')
                    print "TOO SLOW SINGLE PARSE. GIViNG UP:", (time.time() - (start + MAX_SECS_FOR_DEDUP)), len(seenParses)
                    return

                print "TIME TO PREVIEW %s: %s" % (name, time.time() - now)

                try:
                    timediff = now - int(splunk.util.dt2epoch(splunk.util.parseISO(str(events[0]['_time']))))
                    # use the most popular one that doesn't return timestamps that are right now (more than 60 seconds)
                    if abs(timediff) > 10*60:
                        stanzas[name]['count'] = int(stanzas[name]['count']) + 10000
                        print "GOOD TIME:", time.ctime(now - timediff)
                except Exception, e:
                    print "***************", e
                    print 'Stacktrace: %s' % traceback.format_exc()

                    pass

                # normalize my rounding to nearest hour
                relevant = ['%s-=-%s' % (event['_raw'], int(splunk.util.dt2epoch(splunk.util.parseISO(str(event['_time']))))/3600*3600) for event in events]
                #print "RELEVANT:", relevant[:100]
                parseID = hash(str(relevant))
                #print parseID
                #print seenParses
                # remove stanza if it resulted in the same events as the previous 
                if parseID in seenParses:
                    stanzas[name]['count'] = -1
                    #del stanzas[name]
                    print "DELETED DUP PARSE:", name, parseID
                else:
                    print "NEW GOOD PARSE:", name, parseID
                seenParses.add(parseID)
            except Exception, e:
                logger.error('Preview App: Problem deduping %s: %s\n %s' % (name, e, traceback.format_exc()))
                hadErrors = str(e)
        if hadErrors != None:
            self.addMsg('warn', 'Problem deduping some settings (e.g., "%s").  Carrying on.' % hadErrors)



    def getPreviewEvents(self, eventdata, stanza, attrs):
        filename = None
        try:
            f = tempfile.NamedTemporaryFile(delete=False)
            filename = f.name
            f.write(eventdata)
            f.close()
            
            # prefix all stanza attributes with 'props.'
            # give default sourcetype that prevents it from learning sourcetypes
            kwargs = { 'input.path':filename, 'output_mode':'json', 'props.sourcetype': 'default'} 
            for a,v in attrs.items():
                if a == 'count': continue
                kwargs['props.%s' % a] = v

            uri = entity.buildEndpoint("indexing/preview", namespace=self._mynamespace, owner=self._owner)

            print "\tURL: %s ARGS: %s" % (uri, kwargs)
            serverResponse, serverContent = rest.simpleRequest(uri, method='POST', postargs=kwargs, sessionKey=self._sessionKey, raiseAllErrors=True)
            if serverResponse.status not in [200, 201]:
                raise Exception(serverResponse.status, serverResponse.messages)

            # {"messages":[{"type":"INFO","text":"1367872459.2"}]}
            json_content = json.loads(serverContent)
            jobid = json_content["messages"][0]["text"]

            job = splunk.search.getJob(jobid, sessionKey=self._sessionKey)
            events = job.events
            
            #print "\tJOB:", job
            #if len(events) == 0:
            #    print "\tNO EVENTS!"
            #else:
            #    print "\tEVENTS:", events[0]
            return events
        finally:
            if filename:
                os.unlink(filename)

        # jobid = server
        # results = splunk.entity.getEntities('search/jobs/%s/results_preview' % jobid, sessionKey=self._sessionKey, namespace=self._mynamespace, owner=self._owner)

    
def unit_test():

    cherrypy.tools.sessions.on = True    
    class FakeSession(dict):
        def __init__(self):
            self.id = 5
            self.sessionKey = splunk.auth.getSessionKey('admin', 'changeme')
    cherrypy.session = FakeSession()
    cherrypy.session['sessionKey'] = splunk.auth.getSessionKey('admin', 'changeme')
    cherrypy.session['user'] = { 'name': 'admin' }
    cherrypy.session['id'] = 12345
    cherrypy.config['module_dir'] = '/'
    cherrypy.config['build_number'] = '123'
    cherrypy.request.lang = 'en-US'
    # roflcon
    class elvis:
        def ugettext(self, msg):
            return msg
    cherrypy.request.t = elvis()
    # END roflcon

    previewer = PreviewController()

    argc = len(sys.argv)
    if argc == 2:
        datafile = sys.argv[1]
        with open(datafile,"r") as f:
            text = f.read()
            out = previewer.index(data=text, stanza='acr')
        print out
    else:
        print 'Usage: %s datafile' % sys.argv[0]

if __name__ == '__main__':
    unit_test()
