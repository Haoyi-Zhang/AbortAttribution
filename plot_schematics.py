"""Vector drawing primitives; copied into each independent project generator."""
import argparse
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle, Polygon, Circle, FancyArrowPatch

plt.rcParams.update({'font.family':'STIXGeneral', 'mathtext.fontset':'stix',
                     'font.size':9, 'pdf.fonttype':42, 'ps.fonttype':42,
                     'text.usetex':False, 'axes.unicode_minus':False})
CM = 1 / 2.54

class Drawing:
    def __init__(self, bounds):
        x0,y0,x1,y1 = bounds
        self.fig = plt.figure(figsize=((x1-x0)*CM,(y1-y0)*CM))
        self.ax = self.fig.add_axes([0,0,1,1], xlim=(x0,x1), ylim=(y0,y1))
        self.ax.set_aspect('equal'); self.ax.axis('off')
        self.nodes = {}
        self.labels = []

    def text(self,x,y,label,size=9,ha='center',va='center'):
        artist=self.ax.text(x,y,label,fontsize=size,ha=ha,va=va,
                            linespacing=1.15,clip_on=False,zorder=4)
        self.labels.append([artist,None])
        return artist

    def box(self,name,x,y,w,h,label,dashed=False,shape='rect',size=9):
        style = {'edgecolor':'black','facecolor':'white','linewidth':.55,
                 'linestyle':(0,(4,3)) if dashed else 'solid', 'zorder':2}
        if shape == 'diamond':
            obj = Polygon([(x-w/2,y),(x,y+h/2),(x+w/2,y),(x,y-h/2)],**style)
        elif shape == 'circle': obj = Circle((x,y),w/2,**style)
        else: obj = Rectangle((x-w/2,y-h/2),w,h,**style)
        self.ax.add_patch(obj); self.text(x,y,label,size)
        self.labels[-1][1]=(x-w/2,y-h/2,x+w/2,y+h/2)
        self.nodes[name] = (x,y,w,h,shape)

    def point(self,name,side):
        x,y,w,h,_ = self.nodes[name]
        return {'n':(x,y+h/2),'s':(x,y-h/2),'e':(x+w/2,y),
                'w':(x-w/2,y),'nw':(x-w/2,y+h/2),
                'ne':(x+w/2,y+h/2),'c':(x,y)}[side]

    def line(self,points,dashed=False):
        xs,ys=zip(*points)
        self.ax.plot(xs,ys,color='black',linewidth=.55,
                     linestyle=(0,(4,3)) if dashed else 'solid',zorder=1)

    def arrow(self,p,q,dashed=False,via=()):
        points=[p,*via,q]
        if via:self.line(points[:-1],dashed)
        self.ax.add_patch(FancyArrowPatch(points[-2],points[-1],
                         arrowstyle='-|>',mutation_scale=7.5,linewidth=.55,
                         color='black',shrinkA=0,shrinkB=0,
                         linestyle=(0,(4,3)) if dashed else 'solid',zorder=1))

    def edge(self,a,b,sa='s',sb='n',**kwargs):
        self.arrow(self.point(a,sa),self.point(b,sb),**kwargs)

    def frame(self,x,y,w,h):
        self.ax.add_patch(Rectangle((x,y),w,h,fill=False,edgecolor='black',
                                   linewidth=.55,linestyle=(0,(4,3)),zorder=0))

    def save(self,out,name):
        # Fixed physical canvas: do not enlarge or rasterize the scientific figure.
        self.fig.canvas.draw()
        renderer=self.fig.canvas.get_renderer()
        x0,x1=self.ax.get_xlim();y0,y1=self.ax.get_ylim()
        for artist,node in self.labels:
            b=artist.get_window_extent(renderer).transformed(self.ax.transData.inverted())
            if b.x0<x0-.02 or b.x1>x1+.02 or b.y0<y0-.02 or b.y1>y1+.02:
                raise ValueError(name+': clipped label '+repr(artist.get_text()))
            if node and (b.x0<node[0]-.02 or b.x1>node[2]+.02 or b.y0<node[1]-.02 or b.y1>node[3]+.02):
                raise ValueError(name+': label exceeds node '+repr(artist.get_text()))
        self.fig.savefig(out/(name+'.pdf'),format='pdf',
                         metadata={'Creator':'Python Matplotlib','Producer':None,
                                   'CreationDate':None,'ModDate':None})
        plt.close(self.fig)

def observation_pair(out):
    d=Drawing((0,0,15.8,5.5))
    d.box('w',3.7,4.25,6.7,1.55,'Corrupt participant $i$\nAccepts the opening duty\nDoes not submit an opening')
    d.box('h',12.0,4.25,6.7,1.55,'Honest participant $i$\nAccepts the same duty\nSubmits; delivery is suppressed')
    d.box('o',7.9,1.0,12.6,1.5,'Identical authenticated public observation\nAccepted commitment; no opening receipt by $D$\nComplete receipt snapshot through $D$')
    d.arrow(d.point('w','s'),(5.4,1.75));d.text(4.2,2.6,r'$\mathrm{Obs}$')
    d.arrow(d.point('h','s'),(10.4,1.75));d.text(11.6,2.6,r'$\mathrm{Obs}$')
    d.save(out,'observation-pair')

def compiler(out):
    d=Drawing((0,0,15.8,7.8))
    for name,x,y,label in [
        ('base',2.5,6.8,'Base ceremony action\nscalar message $m_{i\\to j,r}$'),
        ('envelope',7.9,6.8,'Signed envelope\n$(C,T,\\pi_{\\mathrm{bind}})$'),
        ('board',13.3,6.8,'Authenticated board\nreceipts and closure'),
        ('recipient',2.5,3.9,'Recipient decrypts\nand checks $R_{\\mathrm{base}}$'),
        ('complaint',7.9,3.9,'Zero-knowledge complaint\n$\\pi_{\\mathrm{bad}}$, if invalid'),
        ('judge',13.3,3.9,'Public judge\nthree evidence classes')]:
        d.box(name,x,y,4.5,1.3,label)
    d.edge('base','envelope','e','w');d.text(5.2,7.6,'compile',8)
    d.edge('envelope','board','e','w');d.text(10.6,7.6,'post',8)
    d.arrow(d.point('envelope','s'),d.point('recipient','n'))
    d.edge('recipient','complaint','e','w');d.text(5.2,3.1,'invalid',8)
    d.edge('complaint','judge','e','w');d.edge('board','judge')
    d.box('out',11.95,1.1,7.0,1.7,'Certificate: bad entry,\nbad delivered message, or\nbounded-service non-opening')
    d.edge('judge','out')
    d.save(out,'compiler')

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--outdir',type=Path,required=True)
    args=parser.parse_args();args.outdir.mkdir(parents=True,exist_ok=True)
    observation_pair(args.outdir);compiler(args.outdir)
